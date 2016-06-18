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
        local servername = ngx.var.server_name
        local time = ngx.localtime()
        if ua then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..tag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..tag.."\"\n"
        end
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename, line)
    end
end

------------------------------------ 规则读取函数 -----------------------------------------
-- function readRule(var)
--     file = io.open(rule_path..'/'..var, "r")
--     if file == nil then
--         return
--     end
--     t = {}
--     for line in file:lines() do
--         table.insert(t, line)
--     end
--     file:close()
--     return(t)
-- end

-- url_rules = readRule('url')
-- white_url_rules = readRule('white_url')
-- args_rules = readRule('args')
-- ua_rules = readRule('user_agent')
-- post_rules = readRule('post')
-- cookie_rules = readRule('cookie')


function debugSay(msg)
    if debug then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(msg)
        ngx.exit(ngx.status)
    end
end


-- function whiteURLCheck()
--     if white_url_rules ~= nil then
--         for _, rule in pairs(white_url_rules) do
--             if ngx_match(ngx.var.uri, rule, "isjo") then
--                 return true
--              end
--         end
--     end
--     return false
-- end


-- function fileExtCheck(ext, black_file_ext)
--     local items = Set(black_fileExt)
--     ext = string.lower(ext)
--     if ext then
--         for rule in pairs(items) do
--             if ngx.re.match(ext, rule, "isjo") then
--                 if attack_log then
--                     log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
--                 end

--                 if debug then
--                     debugSay(ngx.var.request_uri.."-".."file attack with ext: "..ext)
--                 end
--             end
--         end
--     end
--     return false
-- end


-- function set(list)
--     local set = {}
--     for _, l in ipairs(list) do
--         set[l] = true
--     end
--     return set
-- end


-- function checkArgs()
--     for _, rule in pairs(args_rules) do
--         local args = ngx.req.get_uri_args()
--         for key, val in pairs(args) do
--             if type(val) == 'table' then
--                 if val ~= false then
--                     data = table.concat(val, " ")
--                 end
--             else
--                 data = val
--             end
--             if data and type(data) ~= "boolean" and rule ~="" and ngx_match(unescape(data), rule, "isjo") then
--                 log('GET', ngx.var.request_uri, "-", rule)
--                 debugSay(ngx.var.request_uri.."-"..rule)
--                 return true
--             end
--         end
--     end
--     return false
-- end


-- function url()
--     if UrlDeny then
--         for _,rule in pairs(urlrules) do
--             if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
--                 log('GET',ngx.var.request_uri,"-",rule)
--                 say_html()
--                 return true
--             end
--         end
--     end
--     return false
-- end

-- function ua()
--     local ua = ngx.var.http_user_agent
--     if ua ~= nil then
--         for _,rule in pairs(uarules) do
--             if rule ~="" and ngxmatch(ua,rule,"isjo") then
--                 log('UA',ngx.var.request_uri,"-",rule)
--                 say_html()
--             return true
--             end
--         end
--     end
--     return false
-- end

-- function body(data)
--     for _,rule in pairs(postrules) do
--         if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
--             log('POST',ngx.var.request_uri,data,rule)
--             say_html()
--             return true
--         end
--     end
--     return false
-- end

-- function cookie()
--     local ck = ngx.var.http_cookie
--     if CookieCheck and ck then
--         for _,rule in pairs(ckrules) do
--             if rule ~="" and ngxmatch(ck,rule,"isjo") then
--                 log('Cookie',ngx.var.request_uri,"-",rule)
--                 say_html()
--             return true
--             end
--         end
--     end
--     return false
-- end

function denyCC(cc_rate, cc_deny_seconds)
    local uri = ngx.var.uri
    cc_count = tonumber(string.match(cc_rate, '(.*)/'))
    cc_seconds = tonumber(string.match(cc_rate, '/(.*)'))
    local token = getClientIp()..uri
    local limit = ngx.shared.limit
    local req, _ = limit:get(token) -- 127.0.0.1_/price/v1.0: 10
    local ip = getClientIp()
    local block, _ = limit:get(ip) -- 127.0.0.1: 1

    if block then
        if debug then
            ngx.say('Deny by waf.')
            ngx.exit('200')
            return true
        else
            ngx.exit(404)
        end
    end

    if req then
        if req > cc_count then
            limit:set(ip, 1, cc_deny_seconds)
            ngx.exit(404)
            return true
        else
             limit:incr(token, 1)
        end
    else
        limit:set(token, 1, cc_seconds)
    end
    return false
end

-- function get_boundary()
--     local header = get_headers()["content-type"]
--     if not header then
--         return nil
--     end

--     if type(header) == "table" then
--         header = header[1]
--     end

--     local m = match(header, ";%s*boundary=\"([^\"]+)\"")
--     if m then
--         return m
--     end

--     return match(header, ";%s*boundary=([^\",;]+)")
-- end

-- function string.split(str, delimiter)
--         if str==nil or str=='' or delimiter==nil then
--                 return nil
--         end

--     local result = {}
--     for match in (str..delimiter):gmatch("(.-)"..delimiter) do
--         table.insert(result, match)
--     end
--     return result
-- end

function innet(ip, network)
    matched = string.match(network, ip)
    if match then
        return true
    else
        return false
    end
end

function whiteIP()
    if next(ip_white_list) ~= nil then
        ip = getClientIp()
        for _, wip in pairs(ip_white_list) do
            if ip == wip or innet(ip, wip) then
                if debug then
                    ngx.say(ip.."in white list <br />")
                end
                 return true
             end
        end
    end
    return false
end

function blackIP()
     if next(ip_black_list) ~= nil then
        ip = getClientIp()
         for _, bip in pairs(ip_black_list) do
             if ip == bip or ip == "0.0.0.0" or innet(ip, bip) then
                 if debug then
                    ngx.say(ip.."in black list <br/>")
                end
                 ngx.exit(403)
                 return true
             end
         end
     end
     return false
end
