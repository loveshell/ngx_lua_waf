水平太烂，只能在原基础上改改。
1.原cc功能有点弱，改进后可以提高对攻击和普通访问的限制
默认同ip触发规则攻击超过10次/5秒,限制该ip访问nginx服务器1800秒。
同1 ip访问同1地址30次/60秒，限制访问该地址30秒。
2.日志主要是用于syslog服务器能力。
1.--保存日志到syslog,可以用nginx设置的日志服务器保存日志。
logtoserver = "on"
2.--通过加载socket.lua同时使用其他日志服务器，默认关闭。（这个有点粗糙，有需要的自己改）
loghack="off"
3.修改whiteurl，可以针对域名设置白名单。
--whiteurl start
site:^www.baidu.com/whiteurl/
--end


------------------分割线-------------------------------------------------
---------------lovshell记录----------------------------------------------

##ngx_lua_waf

ngx_lua_waf是我刚入职趣游时候开发的一个基于ngx_lua的web应用防火墙。

代码很简单，开发初衷主要是使用简单，高性能和轻量级。

现在开源出来，遵从MIT许可协议。其中包含我们的过滤规则。如果大家有什么建议和想fa，欢迎和我一起完善。

###用途：
    	
	防止sql注入，本地包含，部分溢出，fuzzing测试，xss,SSRF等web攻击
	防止svn/备份之类文件泄漏
	防止ApacheBench之类压力测试工具的攻击
	屏蔽常见的扫描黑客工具，扫描器
	屏蔽异常的网络请求
	屏蔽图片附件类目录php执行权限
	防止webshell上传

###推荐安装:

推荐使用lujit2.1做lua支持

ngx_lua如果是0.9.2以上版本，建议正则过滤函数改为ngx.re.find，匹配效率会提高三倍左右。


###使用说明：

nginx安装路径假设为:/usr/local/nginx/conf/

把ngx_lua_waf下载到conf目录下,解压命名为waf

在nginx.conf的http段添加

		lua_package_path "/usr/local/nginx/conf/waf/?.lua";
        lua_shared_dict limit 10m;
        init_by_lua_file  /usr/local/nginx/conf/waf/init.lua; 
    	access_by_lua_file /usr/local/nginx/conf/waf/waf.lua;

配置config.lua里的waf规则目录(一般在waf/conf/目录下)

        RulePath = "/usr/local/nginx/conf/waf/wafconf/"

绝对路径如有变动，需对应修改

然后重启nginx即可


###配置文件详细说明：

    	RulePath = "/usr/local/nginx/conf/waf/wafconf/"
        --规则存放目录
        attacklog = "off"
        --是否开启攻击信息记录，需要配置logdir
        logdir = "/usr/local/nginx/logs/hack/"
        --log存储目录，该目录需要用户自己新建，切需要nginx用户的可写权限
        UrlDeny="on"
        --是否拦截url访问
        Redirect="on"
        --是否拦截后重定向
        CookieMatch = "on"
        --是否拦截cookie攻击
        postMatch = "on" 
        --是否拦截post攻击
        whiteModule = "on" 
        --是否开启URL白名单
        black_fileExt={"php","jsp"}
        --填写不允许上传文件后缀类型
        ipWhitelist={"127.0.0.1"}
        --ip白名单，多个ip用逗号分隔
        ipBlocklist={"1.0.0.1"}
        --ip黑名单，多个ip用逗号分隔
        CCDeny="on"
        --是否开启拦截cc攻击(需要nginx.conf的http段增加lua_shared_dict limit 10m;)
        CCrate = "100/60"
        --设置cc攻击频率，单位为秒.
        --默认1分钟同一个IP只能请求同一个地址100次
        html=[[Please go away~~]]
        --警告内容,可在中括号内自定义
        备注:不要乱动双引号，区分大小写
        
###检查规则是否生效

部署完毕可以尝试如下命令：        
  
        curl http://xxxx/test.php?id=../etc/passwd
        返回"Please go away~~"字样，说明规则生效。

注意:默认，本机在白名单不过滤，可自行调整config.lua配置


###效果图如下：

![sec](http://i.imgur.com/wTgOcm2.png)

![sec](http://i.imgur.com/DqU30au.png)

###规则更新：

考虑到正则的缓存问题，动态规则会影响性能，所以暂没用共享内存字典和redis之类东西做动态管理。

规则更新可以把规则文件放置到其他服务器，通过crontab任务定时下载来更新规则，nginx reload即可生效。以保障ngx lua waf的高性能。

只记录过滤日志，不开启过滤，在代码里在check前面加上--注释即可，如果需要过滤，反之

###一些说明：

	过滤规则在wafconf下，可根据需求自行调整，每条规则需换行,或者用|分割
	
		args里面的规则get参数进行过滤的
		url是只在get请求url过滤的规则		
		post是只在post请求过滤的规则		
		whitelist是白名单，里面的url匹配到不做过滤		
		user-agent是对user-agent的过滤规则
	

	默认开启了get和post过滤，需要开启cookie过滤的，编辑waf.lua取消部分--注释即可
	
	日志文件名称格式如下:虚拟主机名_sec.log


## Copyright

<table>
  <tr>
    <td>Weibo</td><td>神奇的魔法师</td>
  </tr>
  <tr>
    <td>Forum</td><td>http://bbs.linuxtone.org/</td>
  </tr>
  <tr>
    <td>Copyright</td><td>Copyright (c) 2013- loveshell</td>
  </tr>
  <tr>
    <td>License</td><td>MIT License</td>
  </tr>
</table>
	
感谢ngx_lua模块的开发者[@agentzh](https://github.com/agentzh/),春哥是我所接触过开源精神最好的人


syntax: captures, err = ngx.re.match(subject, regex, options?, ctx?, res_table?)
syntax: from, to, err = ngx.re.find(subject, regex, options?, ctx?, nth?)

Specify options to control how the match operation will be performed. The following option characters are supported:

a             anchored mode (only match from the beginning)

d             enable the DFA mode (or the longest token match semantics).
              this requires PCRE 6.0+ or else a Lua exception will be thrown.
              first introduced in ngx_lua v0.3.1rc30.

D             enable duplicate named pattern support. This allows named
              subpattern names to be repeated, returning the captures in
              an array-like Lua table. for example,
                local m = ngx.re.match("hello, world",
                                       "(?<named>\w+), (?<named>\w+)",
                                       "D")
                -- m["named"] == {"hello", "world"}
              this option was first introduced in the v0.7.14 release.
              this option requires at least PCRE 8.12.

i             case insensitive mode (similar to Perl's /i modifier)

j             enable PCRE JIT compilation, this requires PCRE 8.21+ which
              must be built with the --enable-jit option. for optimum performance,
              this option should always be used together with the 'o' option.
              first introduced in ngx_lua v0.3.1rc30.

J             enable the PCRE Javascript compatible mode. this option was
              first introduced in the v0.7.14 release. this option requires
              at least PCRE 8.12.

m             multi-line mode (similar to Perl's /m modifier)

o             compile-once mode (similar to Perl's /o modifier),
              to enable the worker-process-level compiled-regex cache

s             single-line mode (similar to Perl's /s modifier)

u             UTF-8 mode. this requires PCRE to be built with
              the --enable-utf8 option or else a Lua exception will be thrown.

U             similar to "u" but disables PCRE's UTF-8 validity check on
              the subject string. first introduced in ngx_lua v0.8.1.

x             extended mode (similar to Perl's /x modifier)
