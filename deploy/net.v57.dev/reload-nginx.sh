#!/bin/sh
# /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
# nginx reads certificates at start and reload only.
exec systemctl reload nginx
