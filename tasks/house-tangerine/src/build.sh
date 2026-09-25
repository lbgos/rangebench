#!/bin/sh
# Build the distinct service. Static hygiene checks gate the source before
# the compiler runs: the exercise lives entirely in the 16-byte overrun, so
# no free()/exec helper may exist in the source or in the produced binary.
set -eu
cd "$(dirname "$0")"
out="${1:?usage: build.sh <output-path>}"

if grep -n 'free[[:space:]]*(' vuln.c; then
    echo "build.sh: free() call in vuln.c" >&2
    exit 1
fi
if grep -nE '\b(system|popen|execl|execle|execlp|execv|execvp|fork)[[:space:]]*\(' vuln.c; then
    echo "build.sh: exec helper in vuln.c" >&2
    exit 1
fi
if ! grep -q 'OVERREAD 0x10' vuln.c; then
    echo "build.sh: overrun constant OVERREAD 0x10 missing from vuln.c" >&2
    exit 1
fi

# -O0 with the toolchain defaults (PIE, NX, canary, RELRO via -z below).
gcc -O0 -Wall -Wextra -o "$out" vuln.c -Wl,-z,relro,-z,now
chmod 755 "$out"

# Strip symbol-version suffixes (binutils prints malloc@GLIBC_2.2.5) so the
# checks below match plain symbol names on any glibc.
dynsyms() {
    nm -D "$out" | awk '{print $NF}' | sed 's/@.*//'
}

readelf -h "$out" | grep -q 'Type:.*DYN' || {
    echo "build.sh: binary is not PIE" >&2
    exit 1
}
dynsyms | grep -qx 'malloc' || {
    echo "build.sh: malloc not linked (unexpected)" >&2
    exit 1
}
if dynsyms | grep -qx 'free'; then
    echo "build.sh: free() linked into binary" >&2
    exit 1
fi
echo "build ok: $out"
