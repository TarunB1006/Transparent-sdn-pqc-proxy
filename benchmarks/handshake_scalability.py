#!/usr/bin/env python3
"""
handshake_scalability.py — Measure ML-KEM handshake throughput under concurrent load.

Simulates N simultaneous switch connections hitting the controller (as happens
when Mininet starts and all switches connect at once). Reports mean/p95/p99
latency and throughput at each concurrency level.

Run:
    PYTHONPATH=src python3 benchmarks/handshake_scalability.py
"""

import csv
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqc_sdn.tls.handshake import HybridHandshake
from pqc_sdn.crypto.kem import KemVariant

CONCURRENCY_LEVELS = [1, 4, 8, 16, 32, 64]
HANDSHAKES_PER_LEVEL = 100        # total handshakes at each concurrency
KEM_VARIANTS = [KemVariant.ML_KEM_512, KemVariant.ML_KEM_768, KemVariant.ML_KEM_1024]


def single_handshake(variant: KemVariant) -> float:
    """Run one complete controller↔switch handshake; return elapsed seconds."""
    t0 = time.perf_counter()
    ctrl_hs = HybridHandshake("controller")
    sw_hs   = HybridHandshake("switch-bench")
    hello   = sw_hs.create_client_hello(variant)
    s_hello, cert, encap, _ = ctrl_hs.server_respond(hello)
    sw_hs.client_complete(s_hello, cert, encap)
    return time.perf_counter() - t0


def bench_concurrency(variant: KemVariant, concurrency: int, total: int) -> dict:
    samples = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(single_handshake, variant) for _ in range(total)]
        wall_start = time.perf_counter()
        for f in as_completed(futs):
            try:
                samples.append(f.result() * 1000)  # ms
            except Exception:
                pass
        wall_elapsed = time.perf_counter() - wall_start

    if not samples:
        return {}
    samples.sort()
    n = len(samples)
    return {
        "kem_variant":     variant.value,
        "concurrency":     concurrency,
        "completed":       n,
        "mean_ms":         round(statistics.mean(samples), 3),
        "median_ms":       round(statistics.median(samples), 3),
        "p95_ms":          round(samples[int(0.95 * n)], 3),
        "p99_ms":          round(samples[min(int(0.99 * n), n - 1)], 3),
        "wall_sec":        round(wall_elapsed, 3),
        "throughput_hps":  round(n / wall_elapsed, 1),   # handshakes per second
    }


all_rows = []
for variant in KEM_VARIANTS:
    print(f"\n── {variant.value}")
    print(f"  {'Concurrency':>12}  {'Mean ms':>9} {'p95 ms':>8} {'p99 ms':>8}  {'Tput h/s':>10}")
    print("  " + "-" * 56)
    for c in CONCURRENCY_LEVELS:
        r = bench_concurrency(variant, c, HANDSHAKES_PER_LEVEL)
        if not r:
            continue
        all_rows.append(r)
        print(f"  {c:>12}  {r['mean_ms']:>9.3f} {r['p95_ms']:>8.3f} "
              f"{r['p99_ms']:>8.3f}  {r['throughput_hps']:>10.1f}")

print("\n── Degradation factor (c=64 mean / c=1 mean)")
for variant in KEM_VARIANTS:
    v = variant.value
    base = next((r["mean_ms"] for r in all_rows if r["kem_variant"] == v and r["concurrency"] == 1), None)
    peak = next((r["mean_ms"] for r in all_rows if r["kem_variant"] == v and r["concurrency"] == 64), None)
    if base and peak:
        print(f"  {v:<16}: {base:.3f}ms → {peak:.3f}ms  ({peak/base:.1f}× degradation)")

out = os.path.join(os.path.dirname(__file__), "..", "results", "handshake_scalability.csv")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
    writer.writeheader()
    writer.writerows(all_rows)
print(f"\nSaved → {os.path.relpath(out)}")
