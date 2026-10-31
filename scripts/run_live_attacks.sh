#!/usr/bin/env bash
# Live adversarial campaign (paper Section V-G, Table 7): 16 scenarios x 100
# trials against the real proxies on loopback. No root needed.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=src "${PYTHON:-python3}" -u evaluation/live_attacks.py --trials "${TRIALS:-100}" \
  --out evaluation/results/raw/live_attacks.json
