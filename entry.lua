--------- Global default config -------
require 'config'
--------- Local config setting --------
cc_deny = true
cc_rate = '10/60'

--------- Init project ----------------
require 'init'
--------- Access control limit --------
if ip_check and (whiteIP() or blackIP()) then
elseif cc_deny and denyCC() then
else return
end
