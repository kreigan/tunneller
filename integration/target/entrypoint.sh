#!/bin/sh
set -eu

mkdir -p /www
printf '%s' "${CONTENT:-tunnel-target-ok}" > /www/index.html

exec httpd -f -v -p 8080 -h /www
