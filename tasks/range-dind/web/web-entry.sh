#!/bin/sh
set -e
F1="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$F1" > /home/www/flag1.txt
chmod 400 /home/www/flag1.txt
exec python3 /opt/app.py
