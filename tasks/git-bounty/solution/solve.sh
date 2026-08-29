#!/usr/bin/env bash
# Oracle: unpack the repo, walk history for the removed .env, read the real secret.
set -euo pipefail
cd /work
cp repo-src/repo.tgz . && tar xzf repo.tgz
cd repo
git log --oneline --all -- .env
echo "== historical .env contents =="
for c in $(git rev-list --all); do
  if git ls-tree -r --name-only "$c" | grep -qx ".env"; then
    echo "-- $c"; git show "$c:.env"
  fi
done
