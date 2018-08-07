require 'config'
local match = string.match
--ngx_lua如果是0.9.2以上版本，建议正则过滤函数改为ngx.re.find，匹配效率会提高三倍左右。
--因nginx和lua一起的关系，正则表达式使用\d\w\s会出问题，
--local ngxmatch=ngx.re.match
local ngxmatch=ngx.re.find
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
loghack=optionIsOn(loghack)
--载入socket.lua用于发送log到独立syslog服务器。
local logger = require "socket" 
if loghack then 


	if not logger.initted() then
          local ok, err = logger.init{
              --host = '192.168.0.1',
              host = 'logserver.local',
              port = 514,
              sock_type = "udp", --udp协议
              flush_limit = 1,	--立即发送
              --drop_limit = 5678,
              pool_size = 100,--连接池大小
          }
          if not ok then
              ngx.log(ngx.ERR, "failed to initialize the logger: ",
                      err)
              return
          end
 end
end
					

logpath = logdir 
rulepath = RulePath
logtofile = optionIsOn(logtofile)
logtoserver = optionIsOn(logtoserver)
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
hackipdeny = optionIsOn(hackipdeny)
CCDeny = optionIsOn(CCDeny)
Redirect=optionIsOn(Redirect)
local file = io.open('config')

function getClientIp()
        IP  = ngx.var.remote_addr 
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end
function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function swrite(msg)
      --保存警告等级要高于nginx error_log的默认等级。
			ngx.log(ngx.CRIT,msg)



end

function log(method,url,data,ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        if ua == nil then 
        	ua="null"
        end
        local servername=ngx.var.host
        local time=ngx.localtime()
        if logtofile then
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        line=realIp.." ["..time.."]".."\""..method.." "..servername..url.."\""..data.."\""..ua.."\""..ruletag.."\"".."\n"
        write(filename,line)
        end
        if logtoserver then
        line=realIp.."\""..method.." "..servername..url.."\""..data.."\""..ua.."\""..ruletag.."\""
        --line="lua_waf:"..line
        swrite(line)
        end
    --发送ip到独立syslog服务器。
    if loghack then  local bytes, err = logger.log(getClientIp()) end
		--只要log记录，说明被攻击，利用denyhackip将ip记录。
		if hackipdeny then  denyhackip(0) end
    end
end
------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url')
argsrules=read_rule('args')
uarules=read_rule('user-agent')
wturlrules=read_rule('whiteurl')
postrules=read_rule('post')
ckrules=read_rule('cookie')


function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(html)
        ngx.exit(ngx.status)
    end
end

function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
            --针对site:开始的进行域名匹配。增加白名单用处。
	            local sitemod,_=string.find(rule,"site:")
	        		if sitemod==1 then
	        			rule=string.gsub(rule,"site:","",1)
	        			--调试whiteurl
	        			--if ngx.var.host=='domino.cqhrss.gov.cn' then 
	        			--	log('debug',ngx.var.uri,"",rule)
	        			--end
	        			if ngxmatch(ngx.var.host..ngx.var.uri,rule,"isjo") then
                    return true 
                end
	        		else
            		if ngxmatch(ngx.var.uri,rule,"isjo") then
                    return true 
                end
            	end
            end
        end
    end
    return false
end

function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext=string.lower(ext)
    if ext then
        for rule,_ in pairs(items) do
            if ngxmatch(ext,rule,"isjo") then
            log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
            say_html()
            end
        end
    end
    return false
end
function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end
function args()
    for _,rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val)=='table' then
                 local t={}
                 for k,v in pairs(val) do
                    if v == true then
                        v=""
                    end
                    table.insert(t,v)
                end
                data=table.concat(t, " ")
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
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
      	local m, err = ngx.re.match(CCrate,'([0-9]+)/([0-9]+)/([0-9]+)')
      	local CCcount=tonumber(m[1]) --计数器上限
        local CCseconds=tonumber(m[2]) --计时器
        local CClimits=tonumber(m[3]) --阻止访问时间
        local token = getClientIp()..uri
        local limit = ngx.shared.limit
        local req,_=limit:get(token) --计数器当前值
        
        if req then
            if req > CCcount then
                ngx.exit(404)
                return true
            else
            		if req == CCcount then    limit:set(token,CCcount+1,CClimits)  end
            		
                limit:incr(token,1)
								--调试在syslog日志中查看
								--swrite('计数器:'..token..'当前计数器'..req..'阻止访问时间:'..CClimits)
                 
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

--chk为1表示检测值，不增加，不创建，返回检测结果。
function denyhackip(chk)
    if hackipdeny then
    
       local m, err = ngx.re.match(hackrate,'([0-9]+)/([0-9]+)/([0-9]+)')
      	local hicount=tonumber(m[1]) --计数器上限
        local hiseconds=tonumber(m[2]) --计时器
        local hilimits=tonumber(m[3]) --阻止访问时间
        local token = "hackip"..getClientIp()
        local limit = ngx.shared.limit
        local req,_=limit:get(token) --计数器当前值
        if req then
            if req > hicount then
                ngx.exit(404)
                return true
            else
            		
            		if req == hicount then    
            				limit:set(token,hicount+1,hilimits)	
            				swrite("ip:"..getClientIp().."因攻击被暂停访问"..hilimits.."秒。")
            				end
                 if chk ~=1 then limit:incr(token,1)      end
                --调试在syslog日志中查看
                --swrite("计数器:"..token.."检测状态:"..chk.."当前计数器"..req.."阻止访问时间:"..hilimits)
                
                 
            end
        else
        		if chk ~=1 then limit:set(token,1,hiseconds) 	end
            
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

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
        return false
end

function blockip()
     if next(ipBlocklist) ~= nil then
         for _,ip in pairs(ipBlocklist) do
             if getClientIp()==ip then
                 ngx.exit(403)
                 return true
             end
         end
     end
         return false
end
