#!/usr/bin/env bash
# Oracle: 0.CL double desync + HEAD response-queue shift -> victim bot hit -> flag.
# Offline deterministic: probe gadget -> probe naive 0.CL deadlock -> poison
# loop (fresh connection per attempt) until the flagged cookie reaches us.
set -euo pipefail
python3 /oracle/solve.py
