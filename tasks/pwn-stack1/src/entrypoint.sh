#!/bin/sh
set -e
FLAG="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$FLAG" > /flag
chmod 400 /flag
cp /usr/local/bin/vuln /binshare/vuln
exec socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/usr/local/bin/vuln,stderr
