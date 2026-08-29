#!/bin/sh
set -e
F1="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$F1" > /home/app/flag1.txt
chmod 400 /home/app/flag1.txt
chown app:app /home/app/flag1.txt
# wait for the config share to be provisioned (creds for the internal cfg server)
i=0
while [ ! -s /opt/cfg/prod.ini ] && [ $i -lt 60 ]; do sleep 2; i=$((i+1)); done
exec python3 /opt/app/app.py
