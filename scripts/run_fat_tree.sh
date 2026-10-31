#!/usr/bin/env bash
# Fat-tree data-plane validation (paper Section V-H, Table 9): k = 4, 6, 8, 10.
# Needs root and Mininet; run scripts/gen_ovs_tls_certs.sh first for the
# native OVS TLS baseline.   sudo -E PYTHON=$(which python3) bash scripts/run_fat_tree.sh 5
set -euo pipefail
cd "$(dirname "$0")/.."
RUNS="${1:-5}"
PY="${PYTHON:-python3}"
export PYTHONPATH=src
export PQC_TOPO_RESULTS="${PQC_TOPO_RESULTS:-$(pwd)/evaluation/results/topo_final}"
mkdir -p "$PQC_TOPO_RESULTS"
mn -c >/dev/null 2>&1 || true
"$PY" -u evaluation/topo_comparison.py --k 4,6,8,10 --runs "$RUNS" --three-way \
  2>&1 | tee -a "$PQC_TOPO_RESULTS/run.log"
chown -R "${SUDO_USER:-$(id -un)}" "$PQC_TOPO_RESULTS" 2>/dev/null || true
