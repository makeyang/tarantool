local function table_deepcopy_internal(orig, cyclic)
    local new_cyclic = cyclic or {}
    local copy = orig
    if type(orig) == 'table' then
        local copy_function = getmetatable(orig)
        if copy_function then
            copy_function = copy_function.__copy
        end
        if copy_function == nil then
            copy = {}
            if new_cyclic[orig] ~= nil then
                copy = new_cyclic[orig]
            else
                new_cyclic[orig] = copy
                for orig_key, orig_value in pairs(orig) do
                    copy[orig_key] = table_deepcopy_internal(
                        orig_value,
                        new_cyclic
                    )
                end
            end
        else
            copy = copy_function(orig)
        end
    end
    if cyclic == nil then
        new_cyclic = nil
    end
    return copy
end

local function table_shallowcopy_internal(orig)
    local copy = orig
    if type(orig) == 'table' then
        local copy_function = getmetatable(orig)
        if copy_function then
            copy_function = copy_function.__copy
        end
        if copy_function == nil then
            copy = {}
            for orig_key, orig_value in pairs(orig) do
                copy[orig_key] = orig_value
            end
        else
            copy = copy_function(orig)
        end
    end
    return copy
end

--- Copy any table (shallow and deep version)
-- * deepcopy: copies all levels
-- * shallowcopy: copies only first level
-- Supports __copy metamethod for copying custom tables with metatables
-- @function gsplit
-- @table         inp  original table
-- @shallow[opt]  sep  flag for shallow copy
-- @returns            table (copy)
local function table_copy(orig, shallow)
    local copy = nil
    if shallow then
        copy = table_shallowcopy_internal(orig)
    else
        copy = table_deepcopy_internal(orig, nil)
    end
    return copy
end

-- table library extension
table.copy = table_copy
