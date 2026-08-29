"""Tiny object store: /backup/flag.txt requires ?token=<valid>; tokens are
verified against the live metadata service (single source of truth)."""

import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

META = os.environ.get("META_URL", "http://169.254.169.254")
FLAG = os.environ.get("FLAG", "")


def valid(token: str) -> bool:
    try:
        with urllib.request.urlopen(f"{META}/latest/creds", timeout=5) as r:
            return token == json.loads(r.read()).get("Token")
    except Exception:  # noqa: BLE001
        return False


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
        u = urlparse(self.path)
        if u.path == "/backup/flag.txt":
            if valid((parse_qs(u.query).get("token") or [""])[0]):
                return self._send(200, FLAG)
            return self._send(403, "invalid token")
        if u.path == "/":
            return self._send(200, "objectstore: /backup/flag.txt (auth: ?token=)")
        self._send(404, "no such object")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), H).serve_forever()
