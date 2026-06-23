sudo -u www-data php -r '$_GET["regen"]=1; $_SERVER["PHP_AUTH_USER"]="pass"; $_SERVER["PHP_AUTH_PW"]="word"; $_SERVER["REMOTE_ADDR"]="cli"; include "./post.php";' >/dev/null
