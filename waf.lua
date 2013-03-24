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
local ok, err = sock:setpeername('127.0.0.1', 514)
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

function log(method,url,data)

file=assert(io.open("/data/logs/hack/"..ngx.var.server_name.."_sec.log","a"))
    if data then
      if ngx.var.http_user_agent  then
            file:write(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \""..data.."\" \""..ngx.status.."\" \""..ngx.var.http_user_agent.."\"\n")
			syslog(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \""..data.."\" \""..ngx.status.."\" \""..ngx.var.http_user_agent.."\"\n")
      else
            file:write(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \""..data.."\" \"-\"\n")
			syslog(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \""..data.."\" \"-\"\n")
      end
    else
        if ngx.var.http_user_agent  then
            file:write(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \"-\" \""..ngx.var.http_user_agent.."\"\n")
            syslog(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \"-\" \""..ngx.var.http_user_agent.."\"\n")
        else
            file:write(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \"-\" \"".."-\"\n")
			syslog(ngx.var.remote_addr.." ".." ["..ngx.localtime().."] \""..method.." "..url.."\" \"-\" \"".."-\"\n")
        end
    end
file:close()
end
function check()
    ngx.header.content_type = "text/html"
    ngx.print("just a joke hehe~ !!")
    ngx.exit(200)
end
function read_rule(var)
    file = io.open("/usr/local/nginx/conf/wafconf/"..var,"r")
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    return(table.concat(t,"|"))
end
regex=read_rule('global')
get=read_rule('get')
post=read_rule('post')
agent=read_rule('user-agent')
whitelist=read_rule('whitelist')
if  ngx.re.match(ngx.var.request_uri,whitelist,"i") then
    return
elseif ngx.req.get_body_data() and ngx.re.match(ngx.req.get_body_data(),[[^(?!Content-Disposition: form-data;(.*)filename="(.*).(php|jsp|phtml)").*$]],"i") then
    return
else
    if ngx.re.match(ngx.unescape_uri(ngx.var.request_uri),regex.."|"..get,"isjo") then
        log('GET',ngx.unescape_uri(ngx.var.request_uri))
        check()
    elseif ngx.req.get_body_data() and ngx.re.match(ngx.unescape_uri(ngx.req.get_body_data()),regex,"isjo")then
        log('POST',ngx.unescape_uri(ngx.var.request_uri),ngx.unescape_uri(ngx.req.get_body_data()))
        check()
--    elseif ngx.req.get_headers()["Cookie"] and ngx.re.match(ngx.unescape_uri(ngx.req.get_headers()["Cookie"]),regex,"isjo")then
--        log('COOKIE',ngx.unescape_uri(ngx.var.request_uri),ngx.unescape_uri(ngx.req.get_headers()["Cookie"]))
--        check()
    elseif ngx.var.http_user_agent and ngx.re.match(ngx.var.http_user_agent,regex.."|"..agent,"isjo")  then
        log('USER-AGENT',ngx.unescape_uri(ngx.var.request_uri))
        check()
    elseif ngx.req.get_headers()['Acunetix-Aspect']  then
        ngx.exit(400)
    elseif ngx.req.get_headers()['X-Scan-Memo'] then
        ngx.exit(400)
    else
        return
    end
end
