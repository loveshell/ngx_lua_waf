## ngx_lua_waf
基于 loveshell [nginx-lua-waf](https://github.com/loveshell/ngx_lua_waf)更改

### 使用方法:
1. nginx安装lua模块，不再详述
2. nginx.conf 添加参数
    lua_package_path        /data/server/nginx/conf/waf/?.lua;  # 模块位置
    lua_shared_dict         limit 10m;  # 设置lua使用内存, 根据访问量设置合适值
3. location或server设置访问控制
    access_by_lua_file      /data/server/nginx/conf/waf/entry.lua; # 可以copy一份到不同的配置中，单独修改其配置文件

## 文件说明
- config.lua  默认配置文件
- entry.lua access控制入口样例文件
- init.lua 函数所在文件，都会调用该文件
- wafconf 暂时没有使用，将来开发继续完成


### 参数说明
- debug: 调试阶段开始debug，显示debug信息
- cc_deny: 开启cc_deny，控制访问量
- cc_rate: 10/60 意思为 60s内访问10次，超过频率会被block掉
- cc_deny_seconds: 达到阈值后，禁止访问的时间


