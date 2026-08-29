#!/bin/sh
set -e
FLAG="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$FLAG" > /flag
chmod 400 /flag
cp /opt/lic.jar /binshare/lic.jar
exec socat TCP-LISTEN:9999,reuseaddr,fork EXEC:"java -jar /opt/lic.jar",stderr
