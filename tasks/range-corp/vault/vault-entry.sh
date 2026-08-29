#!/bin/bash
set -e
F3="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$F3" > /home/ops/flag3.txt
chown ops:ops /home/ops/flag3.txt
chmod 400 /home/ops/flag3.txt
ssh-keygen -q -t ed25519 -N '' -f /vaultshare/id_ops -C ops@vault
mkdir -p /home/ops/.ssh
cat /vaultshare/id_ops.pub > /home/ops/.ssh/authorized_keys
chown -R ops:ops /home/ops/.ssh
chmod 600 /home/ops/.ssh/authorized_keys
/usr/sbin/sshd -D -e
