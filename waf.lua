if  ngx.re.match(ngx.var.request_uri,whitelist,"isjo") then
    return
elseif ngx.req.get_body_data() and ngx.re.match(ngx.req.get_body_data(),[[^(?!Content-Disposition: form-data;(.*)filename="(.*).(php|jsp|phtml|asp|aspx|cgi)").*$]],"isjo") then
    return
else
    if ngx.re.match(string.gsub(ngx.unescape_uri(ngx.var.request_uri),"%%",""),regex.."|"..get,"isjo") then
        log('GET',ngx.unescape_uri(ngx.var.request_uri))
        check()
    elseif ngx.req.get_body_data() and ngx.re.match(string.gsub(ngx.unescape_uri(ngx.req.get_body_data()),"%%",""),regex,"isjo")then
        log('POST',ngx.unescape_uri(ngx.var.request_uri),ngx.unescape_uri(ngx.req.get_body_data()))
        check()
--    elseif ngx.req.get_headers()["Cookie"] and ngx.re.match(ngx.unescape_uri(ngx.req.get_headers()["Cookie"]),regex,"isjo")then
--        log('COOKIE',ngx.unescape_uri(ngx.var.request_uri),ngx.unescape_uri(ngx.req.get_headers()["Cookie"]))
--        check()
    elseif ngx.var.http_user_agent and ngx.re.match(ngx.var.http_user_agent,regex.."|"..agent,"isjo")  then
        log('USER-AGENT',ngx.unescape_uri(ngx.var.request_uri))
        check()
    elseif ngx.req.get_headers()['Acunetix-Aspect']  then
        ngx.exit(400)
    elseif ngx.req.get_headers()['X-Scan-Memo'] then
        ngx.exit(400)
    else
        return
    end
end
