"""Portal with LFI on /page and a token-gated /api/dev that proxies to internal ops."""

import os
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PAGES = "/var/www/pages"
TOKEN_FILE = "/etc/portal/token"
OPS = os.environ.get("OPS_URL", "http://ops:9000")


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
        q = parse_qs(u.query)
        if u.path == "/page":
            name = (q.get("name") or [""])[0]
            if not name:
                return self._send(400, "name required")
            try:
                # BUG: no traversal filtering; name is joined onto PAGES and opened
                fname = name if "." in name else f"{name}.html"
                with open(os.path.join(PAGES, fname), "rb") as f:
                    data = f.read(65536)
                self._send(200, data.decode("utf-8", "replace"))
            except OSError as exc:
                self._send(404, f"cannot read page: {exc}")
        elif u.path == "/api/dev":
            path = (q.get("path") or [""])[0]
            token = self.headers.get("X-Dev-Token", "")
            real = ""
            try:
                real = open(TOKEN_FILE).read().strip()
            except OSError:
                return self._send(500, "token backend unavailable")
            if token != real:
                return self._send(403, "bad dev token")
            if not path.startswith("/") or ".." in path:
                return self._send(400, "absolute path required")
            try:
                req = urllib.request.Request(
                    f"{OPS}/exec?path={urllib.parse.quote(path)}", headers={"X-Token": token}
                )
                with urllib.request.urlopen(req, timeout=10) as r:
                    self._send(200, r.read().decode("utf-8", "replace"))
            except Exception as exc:  # noqa: BLE001
                self._send(502, f"ops error: {exc}")
        elif u.path == "/":
            self._send(200, "portal: /page?name=about|contact\n")
        else:
            self._send(404, "not found")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
