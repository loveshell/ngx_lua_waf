--------- Global default config -------
require 'config'
--------- Local config setting --------
cc_deny = true
cc_rate = '10/60'

--------- Init project ----------------
require 'init'
--------- Access control limit --------
if cc_deny and denyCC(cc_rate, cc_deny_seconds) then
elseif ip_check and (whiteIP() or blackIP()) then
else return
end
