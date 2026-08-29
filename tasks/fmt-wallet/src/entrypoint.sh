#!/bin/bash
set -e
FLAG="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$FLAG" > /flag
chmod 400 /flag
cp /usr/local/bin/wallet /binshare/wallet
exec socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/usr/local/bin/wallet,stderr
