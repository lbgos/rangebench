#!/bin/sh
# wait until the seeder has written the repo, then serve it (dumb http git works)
set -e
i=0
while [ ! -f /srv/www/.git/HEAD ] && [ $i -lt 60 ]; do sleep 2; i=$((i+1)); done
exec python3 -m http.server 8080 --directory /srv/www --bind 0.0.0.0
