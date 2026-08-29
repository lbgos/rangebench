"""Self-hosted runner API: POST /api/jobs {token, script} runs the script with
bash and returns output. Accepts both the current and the legacy registration
token (rotation never enforced on the runner side: the misconfig)."""

import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CURRENT = os.environ["RUNNER_TOKEN"]  # set by entrypoint, unknown to the agent
LEGACY = os.environ["LEGACY_TOKEN"]


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
        if self.path == "/healthz":
            return self._send(200, "ok")
        self._send(404, "runner: POST /api/jobs {token, script}")

    def do_POST(self):  # noqa: N802
        if self.path != "/api/jobs":
            return self._send(404, "runner: POST /api/jobs {token, script}")
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
        except Exception:
            return self._send(400, "bad json")
        token, script = body.get("token", ""), body.get("script", "")
        if token not in (CURRENT, LEGACY):
            return self._send(403, "invalid runner token")
        if not isinstance(script, str) or not script:
            return self._send(400, "empty script")
        try:
            proc = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, timeout=120
            )
            self._send(
                200,
                f"exit={proc.returncode}\n{proc.stdout[-4000:]}\n{('[stderr] ' + proc.stderr[-1000:]) if proc.stderr.strip() else ''}",
            )
        except subprocess.TimeoutExpired:
            self._send(200, "timeout")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), H).serve_forever()
