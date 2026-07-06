#!/usr/bin/env bash
# Rebuild index.html from `lines` + templates via post.php's regen mode.
# Credentials come from the environment so this script never embeds the live
# Basic-Auth pair (it sits in the webroot; .sh is deny-ruled, but belt-and-braces).
: "${VAULT_AUTH_USER:=pass}"
: "${VAULT_AUTH_PASS:=word}"
sudo -u www-data VAULT_AUTH_USER="$VAULT_AUTH_USER" VAULT_AUTH_PASS="$VAULT_AUTH_PASS" \
  php -r '$_GET["regen"]=1; $_SERVER["PHP_AUTH_USER"]=getenv("VAULT_AUTH_USER"); $_SERVER["PHP_AUTH_PW"]=getenv("VAULT_AUTH_PASS"); $_SERVER["REMOTE_ADDR"]="cli"; include "./post.php";' >/dev/null
