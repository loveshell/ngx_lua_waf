--配置部分
logpath='/data/logs/hack/'
rulepath='/usr/local/openresty/nginx/conf/ngx_lua_waf/wafconf/'
syslogserver='127.0.0.1'
filext=''
--如果需要开启syslog传输，请取消掉log函数部分的注释
--syslog函数和本地日志记录函数
local bit = require "bit"
local ffi = require "ffi"
local C = ffi.C
local bor = bit.bor
ffi.cdef[[
int write(int fd, const char *buf, int nbyte);
int open(const char *path, int access, int mode);
int close(int fd);
]]

local O_RDWR   = 0X0002; 
local O_CREAT  = 0x0040;
local O_APPEND = 0x0400;
local S_IRUSR = 0x0100;
local S_IWUSR = 0x0080;
function write(logfile,msg)
    local logger_fd = C.open(logfile, bor(O_RDWR, O_CREAT, O_APPEND), bor(S_IRUSR,S_IWUSR));
    local c = msg;
    C.write(logger_fd, c, #c);
    C.close(logger_fd)
end
function syslog(msg)
    ngx.header.content_type = "text/html"
    kern = 0
    user = 1
    mail = 2
    daemon = 3
    auth = 4
    syslog = 5
    lpr = 6
    news = 7
    uucp = 8
    cron = 9
    authpriv = 10
    ftp = 11
    local0 = 16
    local1 = 17
    local2 = 18
    local3 = 19
    local4 = 20
    local5 = 21
    local6 = 22
    local7 = 23

    emerg = 0
    alert = 1
    crit = 2
    err = 3
    warning = 4
    notice = 5
    info = 6
    debug = 7


    local sock = ngx.socket.udp()
    local ok, err = sock:setpeername(syslogserver, 514)
    --上面的ip和端口就是syslog server的ip和端口地址，可自行修改
    if not ok then
        ngx.say("failed to connect to syslog server: ", err)
        return
    end
    level=info
    facility=daemon
    sign=level+facility*8
    ok, err = sock:send('<'..sign..'>'..msg)
    sock:close()
end
function log()
    if ngx.var.http_user_agent  then
        --  syslog(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \"-\" \""..ngx.var.http_user_agent.."\"\n")
        write(logpath..'/'..ngx.var.server_name.."_sec.log",ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..ngx.req.get_method().." "..ngx.var.request_uri.."\" \"-\" \""..ngx.var.http_user_agent.."\"\n")
    else
        --		syslog(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \"-\" \"".."-\"\n")
        write(logpath..'/'..ngx.var.server_name.."_sec.log",ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..ngx.req.get_method().." "..ngx.var.request_uri.."\" \"-\" \"".."-\"\n")
    end
end
------------------------------------规则读取函数-------------------------------------------------------------------
function getrule(method,dict)    
    local waf = dict;
    file = io.open(rulepath..'/'..method,"r")
    t = {}
    for line in file:lines() do
        waf.set(waf,line,true)
    end
    file:close()
end
local update = ngx.shared.update;
local updated_at = update:get("updated_at");
if updated_at == nil or updated_at < ( ngx.now() - 10 ) then
    getrule('urlpath',ngx.shared.urlpath)
    getrule('post',ngx.shared.post)
    getrule('user-agent',ngx.shared.ua)
    getrule('args',ngx.shared.args)

else
    update:set("updated_at", ngx.now());
end
function say_html(ruleid)
    ngx.header.content_type = "text/html"
    ngx.say('Please go away~~~')
    log()
    ngx.exit(200)
end
function args()
    for k,v in pairs(ngx.shared.args:get_keys()) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if ngx.re.match(val,v,"isjo") then
                say_html(k)
                log('GET')
                return true
            end
        end
    end
    return false
end

function url()
    for k,v in pairs(ngx.shared.urlpath:get_keys()) do
        if ngx.re.match(ngx.var.request_uri,v,"isjo") then
            say_html(k)
            log('GET')
            return true
        end
    end
    return false
end

function ua()
    for k,v in pairs(ngx.shared.ua:get_keys()) do
        if ngx.re.match(ngx.var.http_user_agent,v,"isjo") then
            say_html(k)
            log('User-agent')
        end
    end
    return false
end

function body()
    for k,v in pairs(ngx.shared.post:get_keys()) do
        if ngx.req.get_body_data() and ngx.re.match(ngx.req.get_body_data(),v,"isjo") then
            say_html(k)
            log('POST')
            return true
        end
    end
    return false
end
