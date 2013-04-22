ngx.req.read_body()
if ngx.req.get_headers()['Acunetix-Aspect']  then
    ngx.exit(400)
elseif ngx.req.get_headers()['X-Scan-Memo'] then
    ngx.exit(400)
end
if ua() then
elseif url() then
elseif args() then
elseif ngx.req.get_body_data() and  ngx.re.match(ngx.req.get_body_data(),[[Content-Disposition: form-data;(.*)filename=]],"isjo") ==nil  then
    ngx.req.read_body()
    body()
    ngx.req.discard_body()
elseif string.len(filext) >0 then
    if ngx.req.get_body_data() and ngx.re.match(ngx.req.get_body_data(),"Content-Disposition: form-data;(.*)filename=\"(.*)."..filext.."\"","isjo") then
    ngx.exit('Not Allow Uploaded!!')
    end
else
    return
end
 log('User-agent')
