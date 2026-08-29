#!/bin/sh
# Seed a repo whose history contains the real secret, with a decoy in HEAD.
set -e
FLAG="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$FLAG" > /flag
chmod 400 /flag
rm -rf /tmp/repo /srv/repo.tgz
cd /tmp
git init -q repo
cd repo
git config user.email dev@corp.invalid
git config user.name dev
echo "# billing service" > README.md
mkdir -p src
printf 'def charge(u, amt):\n    pass\n' > src/billing.py
git add -A && git commit -qm "init"
printf "DEPLOY_KEY=%s\nSLACK_WEBHOOK=https://hooks.example/T000/B000\n" "$FLAG" > .env
git add .env && git commit -qm "add env config"
echo "retry logic" >> src/billing.py
git add -A && git commit -qm "wip"
git rm -q .env
printf "DEPLOY_KEY=flag{0000-old-rotated-do-not-use-0000}\n" > .env
printf ".env\n" > .gitignore
git add .env .gitignore && git commit -qm "rotate leaked secret, gitignore env"
cd /tmp
tar czf /srv/repo.tgz repo
sleep infinity
