debug = false
rule_path = "/usr/local/nginx/conf/waf/wafconf/"
url_check = false
url_write_check = false
args_check = false
ua_check = false
ua_write_check = false
cookie_check = false
post_check = false

black_file_ext = {"php", "jsp"}
attack_log = false
attach_log_dir = "/usr/local/nginx/logs/hack/"

redirect = false
redirect_url = "http://www.baidu.com"
ip_white_list = {"127.0.0.1", "172.16.1.*"}
ip_black_list = {"1.0.0.1", "172.16.1.*"}

cc_deny = false
cc_rate = "100/60"
cc_deny_seconds = "600"
cc_redirect = false
cc_redirect_url = redirect_url
