--
-- Created by IntelliJ IDEA.
-- User: guang
-- Date: 16/9/22
-- Time: 下午5:59
-- To change this template use File | Settings | File Templates.
--

local _M = {}
_M.version = '0.1.1'


local mt = {__index=_M}

function hello()
    print("hello world")
end

local config = {'hello', 'world' }


function _M.new(self, name)
    name = name or 0
    return setmetatable({name=name}, mt)
end

function _M.get_name(self)
    print(self.name)
end

--function _M.get_version()
--    local name = _M.name()
--    print(name)
--end

return _M

