#!/bin/sh
set -e
F2="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
F3="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$F2" > /tmp/flag2.ref
echo "$F3" > /root/flag3.txt
chmod 400 /root/flag3.txt
dockerd --host=unix:///var/run/docker.sock >/var/log/dockerd.log 2>&1 &
i=0
while ! docker info >/dev/null 2>&1; do
  sleep 1
  i=$((i+1))
  [ $i -gt 60 ] && { cat /var/log/dockerd.log; exit 1; }
done
# Import the Alpine rootfs bundled at build time; the inner daemon has no Internet.
tar -C /opt/alpine-rootfs -cf - . | docker image import - alpine:3.20.6 >/dev/null
# Stopped backup job carrying the docker-era flag in its environment.
docker create --name backup-job -e "FLAG2=$F2" -e "JOB=cron-backup" alpine:3.20.6 /bin/true >/dev/null
exec sleep infinity
