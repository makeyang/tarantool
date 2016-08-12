#!/usr/bin/env tarantool
test_run = require('test_run').new()
ffi = require('ffi')

ffi.cdef('int vy_run_iterator_unit_test(); int vy_mem_iterator_unit_test();')

ffi.C.vy_run_iterator_unit_test()
ffi.C.vy_mem_iterator_unit_test()
