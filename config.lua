debug = false
rule_path = "/data/server/nginx/conf/waf/wafconf/"
url_check = false
url_write_check = false
args_check = false
ua_check = false
ua_write_check = false
cookie_check = false
post_check = false

black_file_ext = {"php", "jsp"}
attack_log = false
attach_log_dir = "/data/logs/waf/"

redirect = false
redirect_url = "http://www.baidu.com"
ip_check = false
ip_white_list = {}  -- {'192.168.1.*', '127.0.0.1'}
ip_black_list = {}  -- {'0.0.0.0', '106.2.34.29'}

cc_deny = false
cc_rate = "100/60"
cc_deny_seconds = "600"
