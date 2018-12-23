## ngx_lua_waf

`ngx_lua_waf`是我刚入职趣游时候开发的一个基于`ngx_lua`的web应用防火墙。

代码很简单，开发初衷主要是使用简单，高性能和轻量级。

现在开源出来，遵从MIT许可协议。其中包含我们的过滤规则。如果大家有什么建议和想fa，欢迎和我一起完善。

### 用途
    	
- 防止`sql`注入，本地包含，部分溢出，`fuzzing`测试，`xss`，`SSRF`等web攻击
- 防止`svn/`备份之类文件泄漏
- 防止`ApacheBench`之类压力测试工具的攻击
- 屏蔽常见的扫描黑客工具，扫描器
- 屏蔽异常的网络请求
- 屏蔽图片附件类目录php执行权限
- 防止`webshell`上传

### 推荐安装

推荐使用`lujit2.1`做lua支持。

`ngx_lua`如果是0.9.2以上版本，建议正则过滤函数改为`ngx.re.find`，匹配效率会提高三倍左右。


### 使用说明

nginx安装路径假设为:`/usr/local/nginx/conf/`。

把`ngx_lua_waf`下载到`conf`目录下,解压命名为waf 。

在`nginx.conf`的`http`段添加：
``` conf
lua_package_path "/usr/local/nginx/conf/waf/?.lua";
lua_shared_dict limit 10m;
init_by_lua_file  /usr/local/nginx/conf/waf/init.lua; 
access_by_lua_file /usr/local/nginx/conf/waf/waf.lua;
```

配置`config.lua`里的waf规则目录(一般在`waf/conf/`目录下)：
``` conf
RulePath = "/usr/local/nginx/conf/waf/wafconf/"
```
绝对路径如有变动，需对应修改。

然后重启nginx即可。


### 配置文件详细说明
``` lua
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
```  
> 备注: 不要乱动双引号，区分大小写。

### 检查规则是否生效

部署完毕可以尝试如下命令：        
``` bash
$ curl http://xxxx/test.php?id=../etc/passwd
```
返回"Please go away~~"字样，说明规则生效。

> 注意: 默认，本机在白名单不过滤，可自行调整`config.lua`配置。


### 效果图

![sec](http://i.imgur.com/wTgOcm2.png)

![sec](http://i.imgur.com/DqU30au.png)

### 规则更新

考虑到正则的缓存问题，动态规则会影响性能，所以暂没用共享内存字典和`redis`之类东西做动态管理。

规则更新可以把规则文件放置到其他服务器，通过`crontab`任务定时下载来更新规则，`nginx reload`即可生效。以保障`ngx lua waf`的高性能。

只记录过滤日志，不开启过滤，在代码里在`check`前面加上`--`注释即可，如果需要过滤，反之。

### 一些说明

过滤规则在`wafconf`下，可根据需求自行调整，每条规则需换行，或者用`|`分割。
	
- `args`里面的规则 get 参数进行过滤的
- `url`是只在 get 请求url过滤的规则		
- `post`是只在 post 请求过滤的规则		
- `whitelist`是白名单，里面的url匹配到不做过滤		
- `user-agent`是对 user-agent 的过滤规则
- 默认开启了get和post过滤，需要开启cookie过滤的，编辑`waf.lua`取消部分`--`注释即可
- 日志文件名称格式如下: `虚拟主机名_sec.log`


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
	
感谢ngx_lua模块的开发者[@agentzh](https://github.com/agentzh/)，春哥是我所接触过开源精神最好的人。
