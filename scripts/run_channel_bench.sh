#!/usr/bin/env bash
# Control-channel experiments on real Open vSwitch (paper Sections V-C to V-F):
# wire bytes, RTT/loss, reconnection storms, switch arrival, new-flow floods and
# traffic analysis. Needs root, Mininet, Open vSwitch and the stunnel/OpenSSL
# baselines (see REPRODUCING.md). Takes many hours with --reps 10.
#   sudo -E PYTHON=$(which python3) bash scripts/run_channel_bench.sh --reps 10
#   ... --exp flood_constrained          (constrained-CPU flood, Fig. 7c/d)
#   ... --pilot                          (1-2 reps, reduced grids, quick check)
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
export PYTHONPATH=src PQC_VENV_PY="$PY"
export PQC_MN_RESULTS="${PQC_MN_RESULTS:-$(pwd)/evaluation/results/mininet}"
mkdir -p "$PQC_MN_RESULTS"
"$PY" -u evaluation/mininet_bench.py "$@" 2>&1 | tee -a "$PQC_MN_RESULTS/run.log"
chown -R "${SUDO_USER:-$(id -un)}" "$PQC_MN_RESULTS" 2>/dev/null || true
