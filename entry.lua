--------- Global default config -------
require 'config'
--------- Local config setting --------
debug = true

cc_deny = false
cc_rate = '10/60'
ip_check = true
ip_white_list = {}
ip_black_list = {}

--------- Init project ----------------
require 'init'
--------- Access control limit --------
if ip_check and (whiteIP(ip_white_list) or blackIP(ip_black_list)) then
elseif cc_deny and denyCC(cc_rate, cc_deny_seconds) then
else return
end
