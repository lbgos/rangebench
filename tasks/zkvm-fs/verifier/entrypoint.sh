#!/bin/bash
# verifier entrypoint: shared harness bundle + socat proof service.
set -euo pipefail

# The statement and guest ELF are baked at build time (hashed statement).
# The flag is generated fresh at every boot and never appears in the image.
FLAG="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$FLAG" > /flag
chmod 400 /flag

# Attacker-side bundle: forge tool + pinned guest program + statement copy.
# Delivered through the shared volume; the agent reads these from /work/harness.
mkdir -p /harness-share
cp /usr/local/bin/nexus-harness /harness-share/forge
cp /etc/zkvm/guest.elf /etc/zkvm/statement /harness-share/
cp /opt/task/harness-README.md /harness-share/README.md
chmod -R a+rX /harness-share

exec socat TCP-LISTEN:31337,reuseaddr,fork \
  EXEC:"/usr/local/bin/nexus-harness serve --statement /etc/zkvm/statement --flag-file /flag",stderr
