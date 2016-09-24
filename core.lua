--
-- Created by IntelliJ IDEA.
-- User: guang
-- Date: 16/9/22
-- Time: 下午7:13
-- To change this template use File | Settings | File Templates.
--


local _M = {}
_M.version = '0.1.0'
log_inited = {}

local get_headers = ngx.req.get_headers
local config = require "config"
local mt = {__index=_M }

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
    local limit = ngx.shared.limit
    local req, _ = limit:get(token)

    if req then
        if req > max_visit then
            ngx.exit(self.config.cc_deny_code)
            return true
        elseif req == max_visit then
            self:log("[Block] " .. token)
            limit:incr(token, 1)
        else
            limit:incr(token, 1)
        end
    else
        limit:set(token, 1, count_period)
    end
end

function _M.log(self, msg)
    if log_inited[self.config.log_path] == nil then
        log_inited[self.config.log_path]  = io.open(self.config.log_path, 'ab')
    end
    self.fd = log_inited[self.config.log_path]

    self.fd:write(msg .. '\n')
    self.fd:flush()
end

function _M.run(self)
    ngx.log(ngx.WARN, 'Start running waf')
    if self.config.cc_deny and self:deny_cc() then
    end
end

return _M
