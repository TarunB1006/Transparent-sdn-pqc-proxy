#!/usr/bin/env bash
# Primitive, cipher-throughput and protocol-level tests (paper Sections V-B,
# V-E and Table 8). No root and no Mininet needed. Writes evaluation/results/raw/.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
export PYTHONPATH=src:.
mkdir -p evaluation/results/raw
"$PY" -u evaluation/run_evaluation.py --preset full --tables 1,2,3,5,6,7,10
"$PY" -u - <<'PYEOF'
import csv
from evaluation.tables.table5b_security_comparative import run
rows = run({'timing_samples': 2000, 'fpr_trials': 5000, 'entropy_msgs': 1000,
            'nonce_empirical': 100000, 'exhaustion_burst': 200, 'multi_algo_iters': 500,
            'tvla_traces': 5000, 'prop_handshakes': 50, 'prop_mutations': 100})
keys = sorted(set().union(*(r.keys() for r in rows)))
with open('evaluation/results/raw/table5c_security_comparative.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore'); w.writeheader(); w.writerows(rows)
PYEOF
# Cipher throughput again with AES-NI masked off in OpenSSL
OPENSSL_ia32cap="~0x200000200000000" "$PY" -u - <<'PYEOF'
import csv
from evaluation.config import FULL
from evaluation.tables import table3_channel
rows = table3_channel.run(FULL)
keys = sorted(set().union(*(r.keys() for r in rows)))
with open('evaluation/results/raw/table3_channel_noaesni.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore'); w.writeheader(); w.writerows(rows)
PYEOF
