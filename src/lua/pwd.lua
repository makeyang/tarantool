local ffi   = require('ffi')
local errno = require('errno')

-- GID_T and UID_T are, essentially, `integer types`.
-- http://pubs.opengroup.org/onlinepubs/009695399/basedefs/sys/types.h.html

-- POSIX demands to have three fields in struct group:
-- http://pubs.opengroup.org/onlinepubs/009695399/basedefs/grp.h.html
-- char   *gr_name The name of the group.
-- gid_t   gr_gid  Numerical group ID.
-- char  **gr_mem  Pointer to a null-terminated array of character pointers to
--                 member names.
--
-- So we'll extract only them.
ffi.cdef[[
    typedef int uid_t;
    typedef int gid_t;
    typedef int time_t;

    struct group {
        char    *gr_name;    /* group name */
        char    *gr_passwd;  /* group password */
        gid_t    gr_gid;     /* group id */
        char   **gr_mem;     /* group members */
    };
]]

-- POSIX demands to have five fields in struct group:
-- char    *pw_name   User's login name.
-- uid_t    pw_uid    Numerical user ID.
-- gid_t    pw_gid    Numerical group ID.
-- char    *pw_dir    Initial working directory.
-- char    *pw_shell  Program to use as shell.
--
-- So we'll extract only them.
if ffi.os == 'OSX' or ffi.os == 'BSD' then
    ffi.cdef[[
        struct passwd {
            char    *pw_name;    /* user name */
            char    *pw_passwd;  /* encrypted password */
            uid_t    pw_uid;     /* user uid */
            gid_t    pw_gid;     /* user gid */
            time_t   pw_change;  /* password change time */
            char    *pw_class;   /* user access class */
            char    *pw_gecos;   /* Honeywell login info */
            char    *pw_dir;     /* home directory */
            char    *pw_shell;   /* default shell */
            time_t   pw_expire;  /* account expiration */
            int      pw_fields;  /* internal: fields filled in */
        };
    ]]
else
    ffi.cdef[[
        struct passwd {
            char *pw_name;   /* username */
            char *pw_passwd; /* user password */
            int   pw_uid;    /* user ID */
            int   pw_gid;    /* group ID */
            char *pw_gecos;  /* user information */
            char *pw_dir;    /* home directory */
            char *pw_shell;  /* shell program */
        };
    ]]
end

ffi.cdef[[
    uid_t          getuid();
    struct passwd *getpwuid(uid_t uid);
    struct passwd *getpwnam(const char *login);
    void           endpwent();
    struct passwd *getpwent();
    void           setpwent();

    gid_t          getgid();
    struct group  *getgrgid(gid_t gid);
    struct group  *getgrnam(gid_t gid);
    struct group  *getgrent();
    void           endgrent();
    void           setgrent();
]]

local function _getpw(uid)
    local pw = nil
    errno(0);
    if type(uid) == 'number' then
        pw = ffi.C.getpwuid(uid)
    elseif type(uid) == 'string' then
        pw = ffi.C.getpwnam(uid)
    else
        error("Bad type of uid (expected 'string'/'number')", 2)
    end
    return pw
end

local function _getgr(gid)
    local gr = nil
    errno(0);
    if type(gid) == 'number' then
        gr = ffi.C.getgrgid(gid)
    elseif type(gid) == 'string' then
        gr = ffi.C.getgrnam(gid)
    else
        error("Bad type of gid (expected 'string'/'number')", 2)
    end
    return gr
end

local pwgr_errstr = "get%s* failed [errno %d]: %s"

local group_cache = setmetatable({}, {
    __call = function(self, gid, force)
        if not force then
            local gr = self[gid]
            if gr then
                return gr
            end
        end
        -- get gr info and parse it
        local gr = _getgr(gid)
        if gr == nil then
            if errno() ~= 0 then
                error(pwgr_errstr:format('pw', errno(), errno.strerror()), 2)
            end
            return nil
        end
        local gr_mem, group_members = gr.gr_mem, {}
        local i = 0
        while true do
            local member = gr_mem[i]
            if member == nil then
                break
            end
            table.insert(group_members, ffi.string(member))
            i = i + 1
        end
        local group = {
            id      = tonumber(gr.gr_gid),
            name    = ffi.string(gr.gr_name),
            members = group_members,
        }
        self[group.name] = group
        self[group.id] = group
        return group
    end
})

local user_cache = setmetatable({}, {
    __call = function(self, uid, force)
        if not force then
            local pw = self[uid]
            if pw then
                return pw
            end
        end
        -- get pw info and parse it
        local pw = _getpw(uid)
        if pw == nil then
            if errno() ~= 0 then
                error(pwgr_errstr:format('pw', errno(), errno.strerror()), 2)
            end
            return nil
        end
        local user = {
            name    = ffi.string(pw.pw_name),
            id      = tonumber(pw.pw_uid),
            group   = group_cache(pw.pw_gid, force),
            workdir = ffi.string(pw.pw_dir),
            shell   = ffi.string(pw.pw_shell),
        }
        self[user.name] = user
        self[user.id] = user
        return user
    end
})

local function getpw(user, force)
    if user == nil then
        user = tonumber(ffi.C.getuid())
    end
    return user_cache(user, force)
end

local function getgr(group, force)
    if group == nil then
        group = tonumber(ffi.C.getgid())
    end
    return group_cache(group, force)
end

local function getpwall(force)
    errno(0);
    local pws = {}
    while true do
        local pw = ffi.C.getpwent()
        if pw == nil then
            break
        end
        table.insert(pws, user_cache(pw.pw_uid, force))
    end
    ffi.C.endpwent();
    if errno() ~= 0 then
        return nil
    end
    return pws
end

local function getgrall(force)
    errno(0);
    local grs = {}
    while true do
        local gr = ffi.C.getgrent()
        if gr == nil then
            break
        end
        table.insert(grs, group_cache(gr.gr_gid, force))
    end
    ffi.C.endgrent();
    if errno() ~= 0 then
        return nil
    end
    return grs
end

return {
    getpw = getpw,
    getgr = getgr,
    getpwall = getpwall,
    getgrall = getgrall,
}
