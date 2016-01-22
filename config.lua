RulePath = "/app/openresty-xwjr/nginx/conf/waf/wafconf/"
attacklog = "on"
logdir = "/var/log/nginx/hack/"
UrlDeny="on"
Redirect="on"
CookieMatch="on"
postMatch="on" 
whiteModule="on" 
black_fileExt={"php","jsp"}
uriWhitelist={"assets", "ccc"}
path403 = "403"
CCDeny="on"
CCrate="240/60"
html=[[
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0.1;url=/403">
<script>window.location.href="/403";<script>
</head>
<body>
<h1>WARNING</h1>
<body>
<html>
]]
html503=[[
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0.1;url=/503">
<script>window.location.href="/503";<script>
</head>
<body>
<h1>WARNING</h1>
<body>
<html>

]]
