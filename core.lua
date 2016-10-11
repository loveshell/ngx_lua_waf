--
-- Created by IntelliJ IDEA.
-- User: ibuler <ibuler@qq.com>
-- Date: 16/9/22
-- Time: 下午7:13
--


local _M = {}
_M.version = '0.1.0'
log_inited = {}

local get_headers = ngx.req.get_headers
local config = require "config"
local iputils = require "iputils"
local mt = {__index=_M }
local limit = ngx.shared.limit
local _cidr_cache = {}

local function get_client_ip()
   local ip = get_headers()["X-Real-IP"]
   if ip == nil then
       ip = ngx.var.remote_addr
   end

   if ip == nil then
       ip = "unkown"
   end
   return ip
end

function _M.table_copy(orig_table)
    local copy = {}

    for k, v in pairs(orig_table) do
        if type(v) ~= "table" then
            copy[k] = v
        else
            copy[k] = _M.table_copy(v)
        end
    end
    return copy
end

function _M.new(self, name)
    local t = {}
    name = name or ""
    t["name"] = name
    t["config"] = _M.table_copy(config.defaults)
    return setmetatable(t, mt)
end

function _M.set_option(self, key, value)
    self["config"][key] = value
end

function _M.deny_cc(self)
    local uri = ngx.var.uri
    local max_visit = tonumber(string.match(self.config.cc_rate, '(.*)/'))
    local count_period = tonumber(string.match(self.config.cc_rate, '/(.*)'))
    local ip = get_client_ip()

    local token = ip..":"..uri
    local req, _ = limit:get(token)

    if req then
        if req > max_visit then
            if self.config.active then
                ngx.exit(self.config.cc_deny_code)
                return true
            else
                return false
            end
        elseif req == max_visit then
            self:log("[Deny_cc] Block "..token)
            limit:incr(token, 1)
            if self.config.active then
                ngx.exit(self.config.cc_deny_code)
            end
            return true
        else
            limit:incr(token, 1)
        end
    else
        limit:set(token, 1, count_period)
    end
end

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

function _M.log(self, msg)
    ngx.log(ngx.WARN, self.config.log_path)
    if log_inited[self.config.log_path] == nil then
        log_inited[self.config.log_path]  = io.open(self.config.log_path, 'a')
    end
    self.fd = log_inited[self.config.log_path]
    if self.config.active then
        self.fd:write(ngx.localtime().." [ACTIVE] ".."["..self.name.."] "..msg..'\n')
    else
        self.fd:write(ngx.localtime().." [MONITOR] ".."["..self.name.."] "..msg..'\n')
    end
    self.fd:flush()
end

function _M.in_white_ip_list(self)
    local ip = get_client_ip()
    local white_ip_token = ip.."white"
    local is_white, _ = limit:get(white_ip_token)

    if is_white then
        return true
    end

    local white_ip_list = self.config.white_ip_list
    if next(white_ip_list) ~= nil then
        if cidr_match(ip, white_ip_list) then
                limit:set(white_ip_token, true, 3600)
                self:log("[White_ip] In white list passed: "..ip)
                return true
        end
    end
    return false
end

function _M.in_black_ip_list(self)
    local ip = get_client_ip()
    local block_ip_token = ip.."block"
    local is_block, _ = limit:get(block_ip_token)

    if is_block then
        if self.config.active then
            ngx.exit(self.config.black_return_code)
        end
        return true
    end

    local black_ip_list = self.config.black_ip_list
    if next(black_ip_list) ~= nil then
        if cidr_match(ip, black_ip_list) then
                limit:set(block_ip_token, true, 3600)
                self:log("[Black_ip] In black list denied: "..ip)
                if self.config.active then
                    ngx.exit(self.config.black_return_code)
                end
                return true
        end
    end
    return false

end

function _M.run(self)
    if self:in_black_ip_list() then
    elseif self:in_white_ip_list() then
    elseif self.config.cc_deny and self:deny_cc() then
    end
end

return _M
