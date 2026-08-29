#!/bin/bash
set -e
F3="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$F3" > /root/flag3
chmod 400 /root/flag3
i=0
while [ ! -s /share/deploy_key.pub ] && [ $i -lt 60 ]; do sleep 2; i=$((i+1)); done
cat /share/deploy_key.pub > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
/usr/sbin/sshd -D -e
