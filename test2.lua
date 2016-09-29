--
-- Created by IntelliJ IDEA.
-- User: guang
-- Date: 16/9/22
-- Time: 下午6:25
-- To change this template use File | Settings | File Templates.
--


--local lua_waf = require "core"
local lua_waf = require "test"
local waf = lua_waf:new("test")

print(waf.name)
--for k, v in pairs(waf["config"]) do
--    print(k, v)
--end
--
--waf:set_option("active", true)
--
--for k, v in pairs(waf["config"]) do
--    pritt(k, v)
--end
--print(waf.config.active)
--
-- waf:deny_cc()
-- waf2:deny_cc()
--waf:log("hello world")
--waf2:log("world")
--waf:get_name()
