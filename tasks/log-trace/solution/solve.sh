#!/usr/bin/env bash
# Oracle: find the brute-forcing IP, its accepted login, then the staged secret in syslog.
set -uo pipefail
cd /work/incident
echo "== brute force sources =="
grep -oE 'Failed password for .* from [0-9.]+' auth.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -5
ATTACKER=$(grep -oE 'Failed password for .* from [0-9.]+' auth.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
echo "attacker ip: $ATTACKER"
grep "Accepted password" auth.log | grep "$ATTACKER"
USER=$(grep "Accepted password" auth.log | grep "$ATTACKER" | awk '{print $9}')
echo "victim: $USER"
echo "== staged secret =="
grep -F "sudo-command: $USER ran:" syslog | sed -n 's/.*printf %s \([A-Za-z0-9+/=]*\) | base64 -d.*/\1/p' | base64 -d
echo
