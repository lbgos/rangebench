"""Internal ops host: runs as root, executes a whitelisted `cat` for holders of the token."""

import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOKEN = os.environ["OPS_TOKEN"]


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
        if u.path != "/exec":
            return self._send(404, "not found")
        if self.headers.get("X-Token", "") != TOKEN:
            return self._send(403, "bad token")
        path = (parse_qs(u.query).get("path") or [""])[0]
        if not path.startswith("/") or ".." in path:
            return self._send(400, "absolute path required")
        proc = subprocess.run(["cat", path], capture_output=True, text=True, timeout=10)
        self._send(200 if proc.returncode == 0 else 500, proc.stdout or proc.stderr)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), H).serve_forever()
