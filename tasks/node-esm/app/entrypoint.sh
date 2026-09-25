#!/bin/sh
set -eu

# Per-boot random flag. /flag is pre-created at build time owned by the app
# user (the service runs unprivileged and cannot create files in /), so the
# unprivileged entrypoint can truncate and rewrite it here.
FLAG="flag{$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
umask 077
printf '%s\n' "$FLAG" > /flag
chmod 400 /flag

cd /app
exec node server.mjs
