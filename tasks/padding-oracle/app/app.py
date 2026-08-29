"""Vault with a padding oracle: AES-128-CBC + MAC. The MAC check runs AFTER
padding removal and the error names the failing stage; that distinction is
the whole vulnerability. Stored plaintext = sha256(flag)[:8] || flag, padded."""

import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from Crypto.Cipher import AES

KEY = os.urandom(16)
FLAG = os.environ["FLAG"]


def pad(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


PLAIN = pad(hashlib.sha256(FLAG.encode()).digest()[:8] + FLAG.encode())
IV = os.urandom(16)
CT = AES.new(KEY, AES.MODE_CBC, IV).encrypt(PLAIN)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: N802
        pass

    def _send(self, code: int, body: str) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.path != "/":
            return self._send(404, "not found")
        self._send(
            200,
            json.dumps(
                {
                    "alg": "AES-128-CBC + SHA256/64 MAC-then-pad",
                    "iv": IV.hex(),
                    "ct": CT.hex(),
                    "try": "POST /try?iv=<hex>&ct=<hex>",
                }
            ),
        )

    def do_POST(self):  # noqa: N802
        if self.path.split("?")[0] != "/try":
            return self._send(404, "not found")
        q = parse_qs(urlparse(self.path).query)
        try:
            iv = bytes.fromhex((q.get("iv") or [""])[0])
            ct = bytes.fromhex((q.get("ct") or [""])[0])
        except ValueError:
            return self._send(400, "bad hex")
        if len(iv) != 16 or not ct or len(ct) % 16:
            return self._send(400, "bad lengths")
        pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
        p = pt[-1]
        if not (1 <= p <= 16) or pt[-p:] != bytes([p]) * p:
            return self._send(200, "BAD-PADDING")
        body = pt[:-p]
        if body[:8] != hashlib.sha256(body[8:]).digest()[:8]:
            return self._send(200, "BAD-MAC")
        return self._send(200, "OK")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
