#!/usr/bin/env bash
# Oracle: unzip jar, read bytecode (or just invert the public affine check),
# submit license, get flag.
set -euo pipefail
mkdir -p /tmp/j && cd /tmp/j && unzip -oq /work/lic/lic.jar Gate.class 2>/dev/null || cp /work/lic/lic.jar .
python3 - > /tmp/license.txt <<'EOF'
A = 0x45d9f3b
C = 0x9e3779b9
T = [0x7c3f1a42 ^ 0x1337, 0x1d0be777 ^ 0x1337, 0x4a2f9c11 ^ 0x1337, 0x65e8b3cd ^ 0x1337]
inv = pow(A, -1, 1 << 32)
print("".join(f"{((t - C) * inv) % (1 << 32):08x}" for t in T))
EOF
cat /tmp/license.txt
(cat /tmp/license.txt; echo) | timeout 20 nc lic 9999
