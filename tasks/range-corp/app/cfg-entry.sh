#!/bin/sh
set -e
F2="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$F2" > /flag2
chmod 400 /flag2
PASS="$(head -c12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
htpasswd -bc /etc/nginx/htpasswd/htpasswd corpdev "$PASS"
# wait for the vault keypair, then assemble the private bundle
i=0
while [ ! -s /vaultshare/id_ops ] && [ $i -lt 60 ]; do sleep 2; i=$((i+1)); done
{
  echo "# ops vault access"
  echo "# flag2: $F2"
  echo "# ssh key for ops@vault (from the last offsite):"
  cat /vaultshare/id_ops
} > /srv/private/core/backup.env
echo "# contacts" > /srv/private/index.html
mkdir -p /share
{
  echo "[config]"
  echo "url = http://cfg/core/backup.env"
  echo "user = corpdev"
  echo "password = $PASS"
} > /share/prod.ini
nginx -g 'daemon off;'
