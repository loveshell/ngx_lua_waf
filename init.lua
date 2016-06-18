-- require 'config'
local match = string.match
local ngx_match = ngx.re.match
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers

function getClientIp()
        IP = get_headers()["X-Real-IP"]
        if IP == nil then
            IP  = ngx.var.remote_addr
        end
        if IP == nil then
            IP  = "unknown"
        end
        return IP
end

function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then
        return
    end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function log(method, url, data, tag)
    if attack_log then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()
        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..tag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..tag.."\"\n"
        end
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
    end
end

------------------------------------ 规则读取函数 -----------------------------------------
function readRule(var)
    file = io.open(rulepath..'/'..var, "r")
    if file == nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t, line)
    end
    file:close()
    return(t)
end

url_rules = readRule('url')
white_url_rules = readRule('white_url')
args_rules = readRule('args')
ua_rules = readRule('user_agent')
post_rules = readRule('post')
cookie_rules = readRule('cookie')


function debugSay(msg)
    if debug then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(msg)
        ngx.exit(ngx.status)
    end
end


function whiteURLCheck()
    if white_url_rules ~= nil then
        for _, rule in pairs(white_url_rules) do
            if ngx_match(ngx.var.uri, rule, "isjo") then
                return true
             end
        end
    end
    return false
end


function fileExtCheck(ext, black_file_ext)
    local items = Set(black_fileExt)
    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext, rule, "isjo") then
                if attack_log then
                    log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
                end

                if debug then
                    debugSay(ngx.var.request_uri.."-".."file attack with ext: "..ext)
                end
            end
        end
    end
    return false
end


function set(list)
    local set = {}
    for _, l in ipairs(list) do
        set[l] = true
    end
    return set
end


function checkArgs()
    for _, rule in pairs(args_rules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val) == 'table' then
                if val ~= false then
                    data = table.concat(val, " ")
                end
            else
                data = val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngx_match(unescape(data), rule, "isjo") then
                log('GET', ngx.var.request_uri, "-", rule)
                debugSay(ngx.var.request_uri.."-"..rule)
                return true
            end
        end
    end
    return false
end


function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
                log('UA',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end

function body(data)
    for _,rule in pairs(postrules) do
        if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
            log('POST',ngx.var.request_uri,data,rule)
            say_html()
            return true
        end
    end
    return false
end

function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxmatch(ck,rule,"isjo") then
                log('Cookie',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
        local uri=ngx.var.uri
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..uri
        local limit = ngx.shared.limit
        local req,_ = limit:get(token)
        local ip = getClientIp()
        local block,_ = limit:get(ip)

        if block then
            ngx.exit(503)
        end

        if req then
            if req > CCcount then
                limit:set(ip,1,DenySeconds)
                ngx.exit(503)
                return true
            else
                 limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function string.split(str, delimiter)
        if str==nil or str=='' or delimiter==nil then
                return nil
        end

    local result = {}
    for match in (str..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match)
    end
    return result
end

function innet(ip, network)
    local star = ''
    for i in string.gmatch(network, '%*') do
        star = star..i
    end

    local ip = string.split(ip, '%.')
    local network = string.split(network, '%.')
    if ip == nil or network == nil then
        return false
    end

    local ip_prefix = {}
    local network_prefix = {}
    for i=1, 4-string.len(star) do
        ip_prefix[i] = ip[i]
        network_prefix[i] = network[i]
    end

    ip_prefix = table.concat(ip_prefix, '.')
    network_prefix = table.concat(network_prefix, '.')

    if ip_prefix == network_prefix then
        return true
    else
        return false
    end
end

function whiteip()
    if next(ipWhitelist) ~= nil then
        ip = getClientIp()
        for _,wip in pairs(ipWhitelist) do
            if ip == wip or innet(ip, wip) then
                return true
            end
        end
    end
        return false
end

function blockip()
     if next(ipBlocklist) ~= nil then
        ip = getClientIp()
         for _,bip in pairs(ipBlocklist) do
             if ip == bip or ip=="0.0.0.0" or innet(ip, bip) then
                 ngx.exit(403)
                 return true
             end
         end
     end
         return false
end
