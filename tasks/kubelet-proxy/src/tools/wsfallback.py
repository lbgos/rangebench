#!/usr/bin/env python3
"""Minimal WebSocket exec client for a kubelet (v4.channel.k8s.io).

stdlib-only websocket fallback for environments without websocat. Performs
the plain HTTP upgrade against a kubelet :10250 exec endpoint, speaks the
v4.channel.k8s.io frame convention (first payload byte selects the stream:
0 stdin, 1 stdout, 2 stderr, 3 error, 4 resize; 0xff closes a stream), and
prints stdout/stderr payloads verbatim. TLS is unverified by default because
kubelet serves a self-signed cert — same as curl -k / websocat --insecure.

Usage:
    wsfallback.py [-H 'Header: value' ...] [-t SECONDS] <wss-url>

    wsfallback.py -t 5 \\
        -H 'Authorization: Bearer TOKEN' \\
        'wss://NODE:10250/exec/<ns>/<pod>/<container>?output=1&error=1&command=cat&command=PATH'

Returns 0 when the server closes cleanly after streaming, 1 on failure.
"""
from __future__ import annotations

import argparse
import base64
import os
import socket
import ssl
import struct
import sys
import urllib.parse

SUBPROTOCOL = "v4.channel.k8s.io"


def fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"wsfallback: {msg}", file=sys.stderr)
    raise SystemExit(1)


def ws_connect(url: str, headers: dict[str, str], timeout: float) -> socket.socket:
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("wss", "ws"):
        fail("url must be wss:// (or ws://)")
    host = u.hostname or fail("missing host in url")
    port = u.port or (443 if u.scheme == "wss" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    sock = socket.create_connection((host, port), timeout=timeout)
    if u.scheme == "wss":
        # Kubelet serving certs are self-signed; verify off by default.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)

    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Protocol: {SUBPROTOCOL}",
    ] + [f"{k}: {v}" for k, v in headers.items()]
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())

    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            fail("connection closed during handshake")
        resp += chunk
    status = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    code = int(status.split(" ")[1]) if len(status.split(" ")) > 1 else 0
    if code != 101:
        body = resp.split(b"\r\n\r\n", 1)[1][:200]
        fail(f"handshake refused: {status}{body.decode(errors='replace')}")
    return sock


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> tuple[int, bytes] | None:
    hdr = recv_exact(sock, 2)
    if len(hdr) < 2:
        return None
    fin = hdr[0] & 0x80
    opcode = hdr[0] & 0x0F
    masked = hdr[1] & 0x80
    length = hdr[1] & 0x7F
    if length == 126:
        ext = recv_exact(sock, 2)
        if len(ext) < 2:
            return None
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext = recv_exact(sock, 8)
        if len(ext) < 8:
            return None
        length = struct.unpack(">Q", ext)[0]
    if masked:  # servers never mask, but tolerate a zero mask
        recv_exact(sock, 4)
    payload = recv_exact(sock, length) if length else b""
    if len(payload) < length:
        return None
    return (opcode, payload) if fin else (opcode, payload)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    # Client frames are masked; random mask per frame.
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    hdr = bytes([0x82, 0x80 | len(payload)]) + mask if len(payload) < 126 else None
    if hdr is None:  # long payloads are unlikely here but handled anyway
        if len(payload) < 1 << 16:
            hdr = bytes([0x82, 0x80 | 126]) + struct.pack(">H", len(payload)) + mask
        else:
            hdr = bytes([0x82, 0x80 | 127]) + struct.pack(">Q", len(payload)) + mask
    sock.sendall(hdr + masked)


def main() -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("-t", "--timeout", type=float, default=15.0)
    ap.add_argument("url")
    args, _ = ap.parse_known_args()

    headers: dict[str, str] = {}
    for h in args.header:
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()

    sock = ws_connect(args.url, headers, args.timeout)
    sock.settimeout(args.timeout)

    out = sys.stdout.buffer
    sent_close = False
    try:
        # Ask for the remote end of stdin so `cat`-style commands exit; a
        # plain 0xff close on stream 0 is the v4 channel close convention.
        send_frame(sock, b"\x00\xff")
        sent_close = True
        while True:
            frame = recv_frame(sock)
            if frame is None:
                break
            opcode, payload = frame
            if opcode == 0x8:  # close
                break
            if opcode == 0x9:  # ping -> pong
                send_frame(sock, bytes([0x8A]) + b"")
                continue
            if opcode not in (0x1, 0x2) or not payload:
                continue
            stream, data = payload[0], payload[1:]
            if stream in (1, 2) and data:  # stdout / stderr
                out.write(data)
                out.flush()
            if stream == 0xFF or (data and data[0] == 0xFF):
                continue
    except (socket.timeout, OSError):
        pass
    finally:
        if not sent_close:
            try:
                send_frame(sock, b"\x00\xff")
            except OSError:
                pass
        try:
            sock.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
