#!/usr/bin/env bash
# Oracle: S0 creds -> S1 API POST 403 -> S2 enumerate -> S3 wss v4 exec ->
# S4 direct-path isolation -> S5 flag print. Stdlib Python, stage-gated.
set -euo pipefail
python3 /oracle/solve.py
