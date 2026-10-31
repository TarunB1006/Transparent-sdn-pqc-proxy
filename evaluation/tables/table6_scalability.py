"""
Table 6 — Scalability & Adaptive Engine.

Tests: handshake latency degradation under concurrent load (1→64 switches),
adaptive cipher switching response time, multi-controller readiness.

All KEM variants swept across concurrency levels.
"""

from __future__ import annotations

import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from evaluation.config import EvalConfig
from evaluation.stats import describe, iqr_clean


def _single_handshake(variant_str: str) -> float:
    from pqc_sdn.tls.handshake import HybridHandshake
    from pqc_sdn.crypto.kem import KemVariant
    variant = KemVariant(variant_str)
    t0 = time.perf_counter()
    sw = HybridHandshake("sw-scale")
    ctrl = HybridHandshake("ctrl-scale")
    hello = sw.create_client_hello(variant)
    sh, cert, encap, _ = ctrl.server_respond(hello)
    sw.client_complete(sh, cert, encap)
    return (time.perf_counter() - t0) * 1000


def run(cfg: EvalConfig) -> List[dict]:
    from pqc_sdn.crypto.kem import KemVariant

    print("\n" + "=" * 72)
    print("TABLE 6 — Scalability & Adaptive Engine")
    print("=" * 72)

    rows = []

    # ── Scalability: all variants × all concurrency levels ────────────────
    for variant in KemVariant:
        print(f"\n  {variant.value}")
        print(f"    {'Conc':>6}  {'Mean ms':>8}  {'p95 ms':>8}  {'p99 ms':>8}  {'Tput h/s':>10}")
        print("    " + "-" * 52)

        for conc in cfg.concurrency_levels:
            samples = []
            with ThreadPoolExecutor(max_workers=conc) as pool:
                futs = [pool.submit(_single_handshake, variant.value)
                        for _ in range(cfg.n_scalability)]
                wall_start = time.perf_counter()
                for f in as_completed(futs):
                    try:
                        samples.append(f.result())
                    except Exception:
                        pass
                wall_elapsed = max(time.perf_counter() - wall_start, 1e-3)  # clamp ≥1ms

            if not samples:
                continue
            stats = describe(iqr_clean(samples))
            throughput = round(len(samples) / wall_elapsed, 1)

            rows.append({
                "table": 6, "mode": "scalability",
                "algorithm": variant.value, "concurrency": conc,
                "wall_sec": round(wall_elapsed, 3),
                "throughput_hps": throughput,
                **stats,
            })
            print(f"    {conc:>6}  {stats['mean']:>8.3f}  {stats['p95']:>8.3f}  "
                  f"{stats['p99']:>8.3f}  {throughput:>10.1f}")

    # ── Degradation factor ────────────────────────────────────────────────
    print("\n  Degradation factor (max_concurrency / single-threaded):")
    for variant in KemVariant:
        v = variant.value
        base = next((r["mean"] for r in rows
                      if r["algorithm"] == v and r["concurrency"] == 1), None)
        peak = next((r["mean"] for r in rows
                      if r["algorithm"] == v
                      and r["concurrency"] == cfg.concurrency_levels[-1]), None)
        if base and peak:
            factor = peak / base
            print(f"    {v:<16} {base:.3f}ms → {peak:.3f}ms  ({factor:.1f}× degradation)")

    # ── Adaptive cipher switching test ────────────────────────────────────
    print("\n  Adaptive cipher switching latency ...")
    try:
        from pqc_sdn.adaptive.monitor import LoadMonitor
        from pqc_sdn.adaptive.selector import AdaptiveSelector

        monitor = LoadMonitor(poll_interval_seconds=0.1)
        selector = AdaptiveSelector(
            monitor,
            cpu_high_pct=200.0,      # disable CPU trigger
            cpu_low_pct=200.0,
            latency_high_ms=200.0,   # disable latency trigger
            latency_low_ms=200.0,
            queue_depth_high=3,      # trigger via queue depth
            queue_depth_low=0,
            hold_seconds=0.2,
        )
        monitor.start()

        # Measure time to switch from auto → ChaCha20 under load
        t0 = time.perf_counter()
        for _ in range(5):
            monitor.notify_handshake_start()
        cipher, changed = selector.check()
        switch_time_ms = (time.perf_counter() - t0) * 1000

        # Clear load and measure revert
        for _ in range(5):
            monitor.notify_handshake_end(0.1)
        time.sleep(0.3)  # wait past hold period
        t1 = time.perf_counter()
        cipher2, changed2 = selector.check()
        revert_time_ms = (time.perf_counter() - t1) * 1000

        monitor.stop()

        print(f"    Load → ChaCha20:  {switch_time_ms:.2f}ms  (changed={changed})")
        print(f"    Clear → Auto:     {revert_time_ms:.2f}ms  (changed={changed2})")

        rows.append({
            "table": 6, "mode": "adaptive_switch",
            "algorithm": "ChaCha20-Poly1305",
            "operation": "load_to_chacha20",
            "latency_ms": round(switch_time_ms, 3),
            "changed": changed,
        })
        rows.append({
            "table": 6, "mode": "adaptive_switch",
            "algorithm": "auto",
            "operation": "clear_to_auto",
            "latency_ms": round(revert_time_ms, 3),
            "changed": changed2,
        })
    except Exception as e:
        print(f"    ⚠ Adaptive engine test skipped: {e}")

    return rows
