--
-- Created by IntelliJ IDEA.
-- User: guang
-- Date: 16/9/22
-- Time: 下午5:59
-- To change this template use File | Settings | File Templates.
--

local _M = {}
_M.version = '0.1.1'

local util = require "resty.waf.util"

local mt = {__index=_M}

function hello()
    print("hello world")
end

local config = {'hello', 'world' }

local _a = {}


function _M:new()
    return setmetatable({}, mt)
end

function _M:name()
    local name = {'guang', 'hong', 'wei' }
    name_new = util.table_copy(name)
    print(table.concat(name_new, ','))
end

function _M.get_version()
    local name = _M.name()
    print(name)
end

return _a

