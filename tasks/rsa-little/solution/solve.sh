#!/usr/bin/env bash
# Oracle: fetch (n,e,c), integer cube root (m^3 = c < n), decode.
set -euo pipefail
curl -s http://kms:8080/ -o /tmp/kms.json
cat /tmp/kms.json; echo
python3 - <<'EOF'
import json
d = json.load(open("/tmp/kms.json"))
n, e, c = d["n"], d["e"], d["c"]
m, hi = 0, 1 << (n.bit_length() // e + 1)
while m < hi:
    mid = (m + hi) // 2
    if mid ** e < c:
        m = mid + 1
    else:
        hi = mid
print("recovered:", m.to_bytes((m.bit_length() + 7) // 8, "big").decode())
EOF
