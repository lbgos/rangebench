#!/bin/bash
set -e
FLAG="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$FLAG" > /root/flag
chmod 400 /root/flag
chown root:root /root/flag
exec socat TCP-LISTEN:31337,reuseaddr,fork,bind=0.0.0.0 EXEC:/usr/local/bin/oneshot,su=dev
