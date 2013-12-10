 local upload = require "upload"
 local content_length=tonumber(ngx.req.get_headers()['content-length'])
local method=ngx.req.get_method()
if whiteip() then
elseif blockip() then
elseif denycc() then
elseif ngx.var.http_Acunetix_Aspect then
    ngx.exit(444)
elseif ngx.var.http_X_Scan_Memo then
    ngx.exit(444)
elseif whiteurl() then
elseif ua() then
elseif url() then
elseif args() then
elseif cookie() then
elseif PostCheck then
    if method=="POST" then   
		local boundary = get_boundary()
		if boundary then
			local form = upload:new(500)
            if not form then
                return
            end
            form:set_timeout(1000) -- 1 sec
            while true do
                local typ, res, err = form:read()
                if not typ then
                    return
                end
                if typ=="body" then
                    body(res)
                end

                if typ == "eof" then
                    break
                end
            end

--            local typ, res, err = form:read()
 --           body(res)
		else
			ngx.req.read_body()
			local args = ngx.req.get_post_args()
			if not args then
				return
			end
			for key, val in pairs(args) do
				if type(val) == "table" then
					data=table.concat(val, ", ")
				else
					data=val
				end
				if data and type(data) ~= "boolean" and body(data) then
                  return true
				end
			end
		end
    end
else
    return
end
