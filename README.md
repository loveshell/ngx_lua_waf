### nginx lua waf

##### 参考
1. https://github.com/loveshell/ngx_lua_waf
2. https://github.com/p0pr0ck5/lua-resty-waf


#### 使用
1. 安装Nginx和lua插件 或者直接安装 openresty
2. git clone 
3. nginx.conf 配置文件
    http段
    ...
    
    lua_package_path "/data/server/nginx/conf/waf/?.lua";
        lua_shared_dict limit 10m;
    ...
    
4. 在location中使用

    location / {
        access_by_lua '
            local lua_waf = require "core"
            local waf = lua_waf:new("default")
            waf:set_option("cc_rate", "2/60")
            waf:set_option("active", true)
            waf:set_option("white_ip_list", {"192.168.128.0/24", "127.0.0.1"})
            waf:run()
        ';
        ...
    }

5. reload

#### 说明
— 默认配置文件

    _M.defaults = {
        active = false,
        cc_deny = true,
        cc_rate = "100/600",
        cc_deny_seconds = 600,
        cc_deny_code = 404,
        log_path = "/tmp/nginx_waf.log",
        white_ip_list = {},
        black_ip_list = {},
        black_return_code = 403,
    }
    
- 单独设置

   waf:set_option("cc_rate", "2/60") 
   
- 问题排查
    nginx error日志 和 log_path
    