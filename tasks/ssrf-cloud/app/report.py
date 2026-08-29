"""Link-preview fetcher with SSRF: blocklist checked on the initial URL only,
redirects followed without re-checking (classic bypass)."""

import re
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BLOCKED = re.compile(
    r"(^|\.)("  # host part
    r"localhost|metadata|169\.254\.|127\.|0\.0\.0\.0|10\.|192\.168\."
    r"|172\.(1[6-9]|2[0-9]|3[01])\."
    r"|\[::1\])",
    re.IGNORECASE,
)


def blocked(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return True
    return bool(BLOCKED.search(host)) or bool(BLOCKED.search(url))


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
        if u.path == "/healthz":
            return self._send(200, "ok")
        if u.path != "/fetch":
            return self._send(404, "usage: /fetch?url=https://example.com")
        url = (parse_qs(u.query).get("url") or [""])[0]
        if not url.startswith(("http://", "https://")):
            return self._send(400, "http(s) only")
        if blocked(url):
            return self._send(403, "blocked: internal addresses are not allowed")
        try:
            # BUG: redirects are followed, and only the initial URL was checked
            with urllib.request.urlopen(url, timeout=8) as r:
                return self._send(
                    200, f"status {r.status}\n{r.read().decode('utf-8', 'replace')[:4000]}"
                )
        except urllib.error.HTTPError as exc:
            self._send(exc.code, f"upstream {exc.code}")
        except Exception as exc:  # noqa: BLE001
            self._send(502, f"fetch error: {exc}")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
