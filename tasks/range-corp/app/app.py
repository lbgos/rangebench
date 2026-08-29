"""Perimeter shop with a pickle-based wishlist import (range-corp stage 1)."""

import base64
import io
import json
import os
import pickle
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FLAG1_FILE = "/home/app/flag1.txt"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: N802
        pass

    def _send(self, code: int, body: str, ctype: str = "text/plain; charset=utf-8") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        if u.path == "/":
            self._send(
                200,
                'shop 4.2\nGET /api/wishlist/export\nPOST /api/wishlist/import {"data": base64}\n',
            )
        elif u.path == "/api/wishlist/export":
            blob = base64.b64encode(pickle.dumps({"items": ["mug", "sticker"], "v": 2})).decode()
            self._send(200, json.dumps({"data": blob}))
        else:
            self._send(404, "not found")

    def do_POST(self):  # noqa: N802
        if self.path != "/api/wishlist/import":
            return self._send(404, "not found")
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
            raw = base64.b64decode(body["data"])
            obj = pickle.load(io.BytesIO(raw))  # VULN: unpickling client data
            out = io.StringIO()
            out.write(f"imported type={type(obj).__name__} value={str(obj)[:2000]}\n")
            return self._send(200, out.getvalue())
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001
            self._send(500, f"import failed: {exc!r}")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
