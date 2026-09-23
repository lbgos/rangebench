#!/bin/sh
# Serve only after the final commit and dumb HTTP metadata are written.
set -e
i=0
while [ ! -s /srv/www/.git/rangebench-ready ] && [ $i -lt 60 ]; do sleep 2; i=$((i+1)); done
test -s /srv/www/.git/rangebench-ready
exec python3 -m http.server 8080 --directory /srv/www --bind 0.0.0.0
