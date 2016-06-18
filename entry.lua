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
if ip_check and (whiteIP() or blackIP()) then
elseif cc_deny and denyCC() then
else return
end
