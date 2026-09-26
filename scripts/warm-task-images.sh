#!/usr/bin/env bash
# Prebuild every task's service images so a network-isolated run host can
# serve docker compose up --build from layer cache alone. Package installs
# (apk/apt) and toolchain downloads (rustup) inside task Dockerfiles need a
# network window exactly once per host; after this script, attempts never do.
# Run with network access: scripts/warm-task-images.sh
set -euo pipefail
cd "$(dirname "$0")/.."
for compose in tasks/*/docker-compose.yml; do
  name=$(basename "$(dirname "$compose")")
  echo "== building ${name}"
  docker compose -f "$compose" build
done
echo "all task service images cached"
