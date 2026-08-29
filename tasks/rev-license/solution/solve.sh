#!/usr/bin/env bash
# Oracle: unpack UPX, pull A/C/T from disassembly (or use known source constants),
# invert d = (T - C) * A^-1 mod 2^32, submit.
set -euo pipefail
upx -d -o /tmp/lic.unpacked /work/lic/lic >/dev/null 2>&1 || cp /work/lic/lic /tmp/lic.unpacked
objdump -d -M intel /tmp/lic.unpacked | grep -E "imul|add" | head -20 || true
python3 - <<'EOF' > /tmp/license.txt
A = 0x5BD1E995
C = 0x9E3779B9
T = [0x7C3F1A42, 0x1D0BE777, 0x4A2F9C11, 0x65E8B3CD]
inv = pow(A, -1, 1 << 32)
print("".join(f"{((t - C) * inv) % (1 << 32):08x}" for t in T))
EOF
cat /tmp/license.txt
(cat /tmp/license.txt; echo) | timeout 10 nc lic 9999
