#!/bin/sh
# Build the reservoir service. Static hygiene checks gate the source before
# the compiler runs: the exercise lives entirely in the drain-then-poke UAF,
# so the frozen protocol literals, the pour whitelist, poke bounds and the
# output discipline are asserted here; no read-back or exec helper may exist
# in the source or in the produced binary.
set -eu
export LC_ALL=C
cd "$(dirname "$0")"
out="${1:?usage: build.sh <output-path>}"
tmpd=$(mktemp -d)
trap 'rm -rf "$tmpd"' EXIT

# 1) Frozen protocol literals (banner, prompts, acks, sizes, bounds).
for lit in \
    "reservoir 1.0" \
    "cell size> " \
    "cell> " \
    "dive off len> " \
    "poured\n" \
    "freed\n" \
    "poked\n" \
    "moored\n" \
    "#define NCELLS 16" \
    "#define POKE_OFF_MAX 0x20000" \
    "#define POKE_LEN_MAX 0x200" \
    "POUR_SIZES[] = {0x28, 0x98, 0x3d8, 0x3e8, 0x408, 0x418, 0x618}"; do
    grep -qF -- "$lit" vuln.c || {
        echo "build.sh: frozen literal missing: $lit" >&2
        exit 1
    }
done

# 2) Writer whitelist: every writer() call must pass one of the frozen
#    string literals, with the frozen occurrence counts (per-handler acks
#    repeat, so counts matter) — nothing may echo cell data back.
grep -oE 'writer\("[^"]*"\)' vuln.c | sort | uniq -c | sed 's/^ *//' | sort > "$tmpd/actual"
cat > "$tmpd/allowed" <<'EOF'
1 writer("1) pour  2) drain  3) poke  4) moor\n")
1 writer("blur\n")
3 writer("bounds\n")
1 writer("cell size> ")
1 writer("cell> ")
1 writer("dive off len> ")
3 writer("dud\n")
1 writer("freed\n")
1 writer("full\n")
1 writer("moored\n")
1 writer("nofit\n")
1 writer("poked\n")
1 writer("poured\n")
1 writer("reservoir 1.0 - 16 cells, nothing is ever forgotten\n")
1 writer("swell\n")
1 writer("waste\n")
1 writer("weir> ")
EOF
sort "$tmpd/allowed" > "$tmpd/allowed.sorted"
if ! diff -u "$tmpd/allowed.sorted" "$tmpd/actual" >&2; then
    echo "build.sh: writer() whitelist mismatch" >&2
    exit 1
fi
if grep -nE 'writer\([^"]' vuln.c | grep -vF 'void writer(const char'; then
    echo "build.sh: writer() with non-literal argument" >&2
    exit 1
fi

# 3) Output/input discipline: output goes through writer() (fputs + explicit
#    flush, each exactly once inside it); no stdio read-back, no buffering
#    mode change, no exec helper anywhere in the source.
fputscount=$(grep -c 'fputs[[:space:]]*(' vuln.c || true)
[ "$fputscount" -eq 1 ] || {
    echo "build.sh: expected exactly one fputs() call site (in writer()), found $fputscount" >&2
    exit 1
}
flushcount=$(grep -c 'fflush[[:space:]]*(' vuln.c || true)
[ "$flushcount" -eq 1 ] || {
    echo "build.sh: expected exactly one fflush() call site (in writer()), found $flushcount" >&2
    exit 1
}
if grep -nE '\b(puts|printf|putchar|fread|fwrite|write|scanf|gets|setvbuf|system|popen|execl|execle|execlp|execv|execvp|fork)[[:space:]]*\(' vuln.c; then
    echo "build.sh: read-back/stdout-mode/exec helper in vuln.c" >&2
    exit 1
fi

# 4) Exactly one free() call site: barn_drain is the whole vulnerability
#    class; no other code path may hand memory back to glibc.
freecalls=$(grep -c 'free[[:space:]]*(' vuln.c || true)
[ "$freecalls" -eq 1 ] || {
    echo "build.sh: expected exactly one free() call site, found $freecalls" >&2
    exit 1
}

# 5) Compile with the toolchain defaults (PIE, NX, canary) plus Full RELRO.
gcc -O0 -Wall -Wextra -o "$out" vuln.c -Wl,-z,relro,-z,now
chmod 755 "$out"

# 6) Link verification: PIE, malloc+free linked, no exec helper linked.
readelf -h "$out" | grep -q 'Type:.*DYN' || {
    echo "build.sh: binary is not PIE" >&2
    exit 1
}
dynsyms() {
    nm -D "$out" | awk '{print $NF}' | sed 's/@.*//'
}
dynsyms | grep -qx 'malloc' || {
    echo "build.sh: malloc not linked (unexpected)" >&2
    exit 1
}
dynsyms | grep -qx 'free' || {
    echo "build.sh: free not linked (unexpected)" >&2
    exit 1
}
if dynsyms | grep -qE '^(system|popen|execl|execle|execlp|execv|execvp|fork)$'; then
    echo "build.sh: exec helper linked into binary" >&2
    exit 1
fi
echo "build ok: $out"
