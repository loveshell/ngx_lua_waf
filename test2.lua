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
local _cidr_cache = {}

print(waf.name)
local iputils = require "iputils"

function cidr_match(ip, cidr_pattern)
	local t = {}
	local n = 1

	if (type(cidr_pattern) ~= "table") then
		cidr_pattern = { cidr_pattern }
	end

	for _, v in ipairs(cidr_pattern) do
		-- try to grab the parsed cidr from out module cache
		local cidr = _cidr_cache[v]

		-- if it wasn't there, compute and cache the value
		if (not cidr) then
			local lower, upper = iputils.parse_cidr(v)
			cidr = { lower, upper }
			_cidr_cache[v] = cidr
		end

		t[n] = cidr
		n = n + 1
	end

	return iputils.ip_in_cidrs(ip, t), ip
end

a = cidr_match('192.168.128.230', {'192.168.128.0/24', '127.0.0.1'})

print(a)

a = cidr_match('172.16.1.1', {'172.16.1.2'})
print(a)

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
