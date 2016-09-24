--
-- Created by IntelliJ IDEA.
-- User: guang
-- Date: 16/9/23
-- Time: 下午4:28
-- To change this template use File | Settings | File Templates.
--

local _M = {}
_M.version = '0.1.0'


_M.defaults = {
    debug = true,
    active = false,
    cc_deny = true,
    cc_rate = "100/600",
    cc_deny_seconds = 600,
    cc_deny_code = 404,
    log_path = "/tmp/nginx_waf.log",
    ip_check= true,
    ip_white_list = nil,
    ip_black_list = nil,
}

return _M
