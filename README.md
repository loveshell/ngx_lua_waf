##ngx_lua_waf

ngx_lua_waf是我刚入职趣游时候开发的一个基于ngx_lua的web应用防火墙。

代码很简单，开发初衷主要是使用简单，高性能和轻量级。

现在开源出来.其中包含我们的过滤规则。如果大家有什么建议和想fa，欢迎和我一起完善。

###用途：
		
	防止sql注入，本地包含，部分溢出，fuzzing测试，xss,SSRF等web攻击
	防止svn/备份之类文件泄漏
	防止ApacheBench之类压力测试工具的攻击
	屏蔽常见的扫描黑客工具，扫描器
	屏蔽异常的网络请求
	屏蔽图片附件类目录php执行权限
	防止webshell上传

###效果图如下：

![sec](http://www.sectop.org/wp-content/uploads/2013/03/QQ截图20130323150826.jpg)

###推荐安装:

请自行给nginx安装ngx_lua模块，推荐lujit2.0做lua支持

请提前新建/data/logs/hack/目录攻击日志，并赋予nginx用户对该目录的写入权限。


###配置部分：

	编辑init.lua配置部分
	logpath='/data/logs/hack/'
	rulepath='/usr/local/nginx/conf/wafconf/'
	syslogserver='127.0.0.1'
	如果需要开启syslog传输，请取消掉log函数部分的注释

	在nginx.conf的http段添加
	lua_need_request_body on;（开启post请求）	
	init_by_lua_file  /usr/local/nginx/conf/init.lua; 
	access_by_lua_file /usr/local/nginx/conf/waf.lua;
	
	注意:第一次安装配置好需要重启nginx

###规则更新：

考虑到正则的缓存问题，动态规则会影响性能，所以暂没用共享内存字典和redis之类东西做动态管理。

规则更新可以把规则文件放置到其他服务器，通过crontab任务定时下载来更新规则，nginx reload即可生效。以保障ngx lua waf的高性能。

只记录过滤日志，不开启过滤，在代码里在check前面加上--注释即可，如果需要过滤，反之

###一些说明：

	过滤规则在wafconf下，可根据需求自行调整，每条规则需换行,或者用|分割
	
		global是全局过滤文件，里面的规则对post和get都过滤		
		get是只在get请求过滤的规则		
		post是只在post请求过滤的规则		
		whitelist是白名单，里面的url匹配到不做过滤		
		user-agent是对user-agent的过滤规则
	

	默认开启了get和post过滤，需要开启cookie过滤的，编辑waf.lua取消部分--注释即可
	
	日志文件名称格式如下:虚拟主机名_sec.log


###关于

欢迎大家到http://bbs.linuxtone.org 多多交流

weibo: [@ppla](http://weibo.com/opscode)
	
感谢ngx_lua模块的开发者[@agentzh](https://github.com/agentzh/),春哥是我所接触过开源精神最好的人
