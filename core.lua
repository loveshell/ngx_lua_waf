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
            if self.config.active then
                ngx.exit(self.config.cc_deny_code)
                return true
            else
                return false
            end
        elseif req == max_visit then
            if self.config.active then
                self:log("[Deny_cc] Block " .. token)
                ngx.exit(self.config.cc_deny_code)
            else
                self:log("[Deny_cc] FakeBlock " .. token)
            end
            limit:incr(token, 1)
            return true
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

function _M.in_white_ip_list(self)
    local ip = get_client_ip()
    local is_white_token = ip.."white"
    local is_white, _ = limit:get(is_white_token)

    if is_white then
        return true
    end

    if next(white_ip_list) ~= nil then
        local white_ip_list = self.config.white_ip_list
        for _, wip in paris(white_ip_list) do
            if ip == wip or iputils.ip_in_cidrs(ip, wip) then
                return true
            end
        end
    end
    return false
end

function _M.in_black_ip_list(self)
    local limit = ngx.shared.limit
    local ip = get_client_ip()
    local is_block_token = ip.."block"
    local is_block, _ = limit:get(is_block_token)
    if is_block then
        ngx.exit(self.config.ip_black_code)
        return true
    end
    if next(white_ip_list) ~= nil then
        local black_ip_list = self.config.white_ip_list
        for _, bip in paris(black_ip_list) do
            if ip == bip or iputils.ip_in_cidrs(ip, bip) then
                limit:set(is_block_token, true, 3600)
                ngx.exit(self.config.ip_black_code)
                return true
            end
        end
    end
    return false

end

function _M.run(self)
    ngx.log(ngx.WARN, 'Start running waf')
    if self:in_black_ip_list() then
    elseif self:in_white_ip_list() then
    elseif self.config.cc_deny and self:deny_cc() then
    end
end

return _M
