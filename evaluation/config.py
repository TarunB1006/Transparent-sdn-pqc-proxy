"""
Unified evaluation configuration.

All tunables in one place. No magic numbers elsewhere.
Methodology adapted from pqc-iot-benchmark (ANOVA/TOPSIS weights)
and PQC-LEO (warmup, multi-run averaging).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVAL_ROOT = Path(__file__).resolve().parent
RESULTS_DIR = EVAL_ROOT / "results"
RAW_DIR = RESULTS_DIR / "raw"
CLEANED_DIR = RESULTS_DIR / "cleaned"
ANALYSIS_DIR = RESULTS_DIR / "analysis"
FIGURES_DIR = RESULTS_DIR / "figures"

for _d in (RAW_DIR, CLEANED_DIR, ANALYSIS_DIR, FIGURES_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ── Statistical parameters (from pqc-iot-benchmark methodology) ───────────────
SIGNIFICANCE_LEVEL = 0.05      # alpha for ANOVA / Tukey HSD
WARMUP_ITERATIONS = 10         # discard first N (PQC-LEO approach)
IQR_MULTIPLIER = 1.5           # standard IQR outlier fence
RANDOM_SEED = 42

# ── TOPSIS weights (from pqc-iot-benchmark, adapted for SDN context) ─────────
TOPSIS_WEIGHTS = {
    "handshake_latency": 0.25,
    "per_frame_latency": 0.20,
    "wire_overhead":     0.15,
    "memory_kb":         0.15,
    "throughput_mbs":    0.15,
    "security_bits":     0.10,
}


@dataclass
class EvalConfig:
    """Master configuration for the evaluation run."""

    # ── Iteration counts ──────────────────────────────────────────────────
    n_primitive: int = 500           # KEM/DSA micro-op iterations
    n_handshake: int = 200           # full handshake iterations per variant
    n_classical_tls: int = 100       # classical TLS 1.3 baseline
    n_proxy: int = 1000              # encrypt/decrypt per payload size
    n_cipher: int = 1000             # symmetric cipher per payload size
    n_policy: int = 1000             # policy engine iterations
    n_attack: int = 2000             # attack overhead per scenario
    n_hndl_brute: int = 10_000       # HNDL brute-force attempts
    n_scalability: int = 100         # handshakes per concurrency level

    # ── Payload sizes ─────────────────────────────────────────────────────
    proxy_payloads: List[int] = field(
        default_factory=lambda: [64, 128, 256, 512, 1024, 4096]
    )
    cipher_payloads: List[int] = field(
        default_factory=lambda: [64, 256, 1024, 4096, 16384]
    )

    # ── Scalability ───────────────────────────────────────────────────────
    concurrency_levels: List[int] = field(
        default_factory=lambda: [1, 4, 8, 16, 32, 64]
    )

    # ── Three-way comparison modes ────────────────────────────────────────
    # Mode A: No PQC (classical X25519 + Ed25519)
    # Mode B: Standard PQC TLS 1.3 (ML-KEM via OpenSSL)
    # Mode C: Our implementation (ML-KEM + custom proxy + DSCP adaptive)
    modes: List[str] = field(
        default_factory=lambda: ["classical", "standard_pqc_tls", "pqc_sdn_proxy"]
    )

    # ── Which tables to run ───────────────────────────────────────────────
    run_tables: List[int] = field(
        default_factory=lambda: [1, 2, 3, 4, 5, 6, 7, 8]
    )


# ── Presets ───────────────────────────────────────────────────────────────────
FAST = EvalConfig(
    n_primitive=50, n_handshake=20, n_classical_tls=10,
    n_proxy=100, n_cipher=100, n_policy=100,
    n_attack=200, n_hndl_brute=1000, n_scalability=20,
    proxy_payloads=[64, 1024],
    cipher_payloads=[64, 1024],
    concurrency_levels=[1, 4, 16],
)

FULL = EvalConfig()  # publication quality — defaults
