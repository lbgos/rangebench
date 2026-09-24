#!/bin/sh
set -e
F1="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$F1" > /flag1
chmod 400 /flag1
LEGACY="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
rm -rf /site/www/.git /site/www/* /site/staging
mkdir -p /site/www /share
echo "reg_$LEGACY" > /share/legacy_token
cd /site/www
git init -q .
git config user.email ci@corp.invalid
git config user.name ci-bot
echo "# corp site" > index.html
cat > .gitlab-ci.yml <<EOF
stages: [build, deploy]
variables:
  DEPLOY_ENV: prod
  NOTES_FLAG: $F1
build-job:
  script: [ "make all" ]
EOF
git add -A && git commit -qm "site + ci"
# the leak: registration token committed, then rotated only in a later commit
cat > runner.env <<EOF
RUNNER_API=http://runner:9000/api/jobs
RUNNER_TOKEN=reg_$LEGACY
EOF
git add runner.env && git commit -qm "wip: runner wiring"
echo "runner rotated" >> index.html
rm runner.env
cat > .gitlab-ci.yml <<EOF
stages: [build, deploy]
variables:
  DEPLOY_ENV: prod
  NOTES_FLAG: $F1
build-job:
  script: [ "make all" ]
EOF
git add -A && git commit -qm "rotate runner token, drop runner.env"
git update-server-info
printf 'ready\n' > .git/rangebench-ready
echo "seeded: legacy=reg_$LEGACY"
sleep infinity
