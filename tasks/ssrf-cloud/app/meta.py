"""Fake cloud metadata: hands out per-run tokens."""

import json
import random
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "".join(random.choice("0123456789abcdef") for _ in range(40))


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: N802
        pass

    def do_GET(self):  # noqa: N802
        if self.path == "/latest/creds":
            body = json.dumps(
                {
                    "Code": "Success",
                    "Type": "AWS-HMAC-Token",
                    "Token": TOKEN,
                    "TokenScope": "boot",
                }
            ).encode()
        else:
            body = json.dumps({"error": "not found", "hint": "/latest/creds"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
