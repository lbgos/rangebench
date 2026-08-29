"""Status page with a command-injection ping utility (range-dind stage 1)."""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


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
        q = parse_qs(u.query)
        if u.path == "/":
            self._send(200, "infra status: all green\nusage: /ping?host=<host>")
        elif u.path == "/ping":
            host = (q.get("host") or ["8.8.8.8"])[0]
            # BUG: host is spliced into a shell command
            out = os.popen(f"ping -c1 -W2 {host} 2>&1; echo").read()
            self._send(200, out[:8000])
        else:
            self._send(404, "not found")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
