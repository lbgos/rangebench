#!/bin/sh
set -e
F2="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
mkdir -p /flags
echo "$F2" > /flags/stage2
chmod 400 /flags/stage2
CURRENT="reg_$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
i=0
while [ ! -s /share/legacy_token ] && [ $i -lt 60 ]; do sleep 2; i=$((i+1)); done
LEGACY=$(cat /share/legacy_token)
mkdir -p /root/.ssh
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519 -C deploy
cp /root/.ssh/id_ed25519.pub /share/deploy_key.pub
export RUNNER_TOKEN="$CURRENT" LEGACY_TOKEN="$LEGACY"
exec python3 /opt/runner.py
