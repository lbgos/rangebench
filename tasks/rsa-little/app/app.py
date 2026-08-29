"""KMS: publishes n, e=3, c = m^3 mod n where m^3 < n (no padding, tiny exponent)."""

import json
import os
import random
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ["FLAG"]


def prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if all(pow(random.randint(2, p - 1), p - 1, p) == 1 for _ in range(40)):
            return p


n = prime(512) * prime(512)
e = 3
m = int.from_bytes(FLAG.encode(), "big")
assert m**3 < n, "flag too long for cube-root attack"
c = pow(m, e, n)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: N802
        pass

    def do_GET(self):  # noqa: N802
        body = json.dumps({"scheme": "RSA-broadcast", "n": n, "e": e, "c": c}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
