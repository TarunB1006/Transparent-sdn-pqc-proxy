#!/usr/bin/env python3
"""
PQC-SDN Unified Evaluation Framework
=====================================

One script. Six tables. Three-way comparison (classical vs standard PQC vs our proxy).
Statistical rigor: IQR outlier cleaning, ANOVA significance testing, TOPSIS ranking.

Incorporates methodology from:
  - PQC-LEO (Turino et al., IEEE TPS-ISA 2025): multi-run averaging, CoV, key sizes
  - pqc-iot-benchmark: IQR cleaning, ANOVA + Tukey HSD, TOPSIS, descriptive stats
  - FuzzSDN (Ollando et al.): attack simulation, failure detection rate

Usage:
    # Fast run (for testing — ~2 min)
    PYTHONPATH=src python evaluation/run_evaluation.py --preset fast

    # Full run (publication quality — ~15 min)
    PYTHONPATH=src python evaluation/run_evaluation.py --preset full

    # Select specific tables
    PYTHONPATH=src python evaluation/run_evaluation.py --tables 1,2,5

    # Custom iterations
    PYTHONPATH=src python evaluation/run_evaluation.py --n-primitive 1000 --n-handshake 500
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

# Ensure src/ is on the path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from evaluation.config import EvalConfig, FAST, FULL, RESULTS_DIR, RAW_DIR, ANALYSIS_DIR


def _save_csv(rows: list, filename: str) -> Path:
    """Save rows (list of dicts) to CSV."""
    if not rows:
        return Path("/dev/null")
    path = RAW_DIR / filename
    fieldnames = list(rows[0].keys())
    # Gather all keys across all rows (some rows may have extra keys)
    for r in rows:
        for k in r.keys():
            if k not in fieldnames:
                fieldnames.append(k)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"  → Saved {len(rows)} rows to {path}")
    return path


def _run_anova_on_results(all_rows: list) -> list:
    """Run ANOVA across modes for key metrics, return analysis rows."""
    from evaluation.stats import run_anova, run_tukey_hsd

    analysis = []

    # Group handshake latency by mode
    handshake_rows = [r for r in all_rows if r.get("table") == 2 and r.get("concurrency") == 1]
    if len(handshake_rows) >= 2:
        # We don't have raw samples in the rows — ANOVA needs them.
        # For now, report the comparison as a structured result.
        # Full ANOVA would need storing raw samples separately.
        pass

    # ANOVA on crypto primitives: PQC vs classical per operation
    prim_rows = [r for r in all_rows if r.get("table") == 1]
    ops = set(r["operation"] for r in prim_rows if "operation" in r)

    for op in sorted(ops):
        groups = {}
        for r in prim_rows:
            if r.get("operation") == op:
                key = r.get("mode", "unknown")
                # Use mean as a single-point for this group
                # (full ANOVA would need raw samples — future enhancement)
                groups.setdefault(key, []).append(r["mean"])

        if len(groups) >= 2 and all(len(v) > 0 for v in groups.values()):
            try:
                result = run_anova(groups)
                result["operation"] = op
                result["comparison"] = "classical_vs_pqc"
                analysis.append(result)
            except Exception:
                pass

    return analysis


def _run_topsis(all_rows: list) -> list:
    """Run TOPSIS on handshake variants."""
    from evaluation.stats import topsis_rank

    handshake_rows = [r for r in all_rows
                      if r.get("table") == 2
                      and r.get("mode") == "C_pqc_sdn"
                      and r.get("concurrency") == 1]

    if len(handshake_rows) < 2:
        return []

    alternatives = [r["algorithm"] for r in handshake_rows]
    criteria = {
        "handshake_latency": [r["mean"] for r in handshake_rows],
        "per_frame_latency": [r.get("p99", r["mean"]) for r in handshake_rows],
    }

    # Add channel overhead if available
    channel_rows = [r for r in all_rows if r.get("table") == 3 and r.get("operation") == "roundtrip"]
    if channel_rows:
        # Use 64B payload overhead for each cipher
        for algo in alternatives:
            pass  # TOPSIS on handshake variants, not cipher variants

    return topsis_rank(alternatives, criteria)


def main():
    parser = argparse.ArgumentParser(description="PQC-SDN Unified Evaluation")
    parser.add_argument("--preset", choices=["fast", "full"], default="fast",
                        help="Preset: fast (~2min) or full (~15min)")
    parser.add_argument("--tables", type=str, default=None,
                        help="Comma-separated table numbers to run (e.g. 1,2,5)")
    parser.add_argument("--n-primitive", type=int, default=None)
    parser.add_argument("--n-handshake", type=int, default=None)
    parser.add_argument("--n-proxy", type=int, default=None)
    args = parser.parse_args()

    # Build config
    cfg = FAST if args.preset == "fast" else FULL
    if args.n_primitive:
        cfg.n_primitive = args.n_primitive
    if args.n_handshake:
        cfg.n_handshake = args.n_handshake
    if args.n_proxy:
        cfg.n_proxy = args.n_proxy
    if args.tables:
        cfg.run_tables = [int(t) for t in args.tables.split(",")]

    print("╔" + "═" * 70 + "╗")
    print("║  PQC-SDN Unified Evaluation Framework".ljust(71) + "║")
    print("║  Methodology: PQC-LEO + pqc-iot-benchmark + FuzzSDN".ljust(71) + "║")
    print("╚" + "═" * 70 + "╝")
    print(f"\n  Preset:     {args.preset}")
    print(f"  Tables:     {cfg.run_tables}")
    print(f"  Primitives: {cfg.n_primitive} iterations")
    print(f"  Handshake:  {cfg.n_handshake} iterations")
    print(f"  Proxy:      {cfg.n_proxy} iterations")
    print(f"  Output:     {RESULTS_DIR}/")

    # ── Start the live stack ONCE — keeps running for all tables ──────────
    print("\n" + "=" * 72)
    print("STARTING PQC-SDN LIVE STACK")
    print("=" * 72)
    from evaluation.stack_manager import StackManager
    stack = StackManager(startup_timeout=30, reuse_running=True)
    stack.start()
    if stack.is_up:
        print(f"  Stack: Ryu:6653 ctrl_proxy:6652 sw_proxy:6634 ✓")
    else:
        print("  Stack: ⚠ failed to start — live-stack tests will be skipped")

    t_start = time.perf_counter()
    all_rows = []

    try:
        # ── Table 1: Raw Primitives ───────────────────────────────────────
        if 1 in cfg.run_tables:
            from evaluation.tables import table1_primitives
            t1_rows = table1_primitives.run(cfg)
            _save_csv(t1_rows, "table1_primitives.csv")
            all_rows.extend(t1_rows)

    # ── Table 2: Handshake Protocol ───────────────────────────────────────
        if 2 in cfg.run_tables:
            from evaluation.tables import table2_handshake
            t2_rows = table2_handshake.run(cfg)
            _save_csv(t2_rows, "table2_handshake.csv")
            all_rows.extend(t2_rows)

        # ── Table 3: Channel Overhead ─────────────────────────────────────────
        if 3 in cfg.run_tables:
            from evaluation.tables import table3_channel
            t3_rows = table3_channel.run(cfg)
            _save_csv(t3_rows, "table3_channel.csv")
            all_rows.extend(t3_rows)

        # ── Table 4: SDN Network ─────────────────────────────────────────────
        if 4 in cfg.run_tables:
            from evaluation.tables import table4_sdn
            t4_rows = table4_sdn.run(cfg)
            if t4_rows:
                _save_csv(t4_rows, "table4_sdn.csv")
                all_rows.extend(t4_rows)

        # ── Table 5: Security ─────────────────────────────────────────────────
        if 5 in cfg.run_tables:
            from evaluation.tables import table5_security
            t5_rows = table5_security.run(cfg)
            _save_csv(t5_rows, "table5_security.csv")
            all_rows.extend(t5_rows)

        # ── Table 6: Scalability ──────────────────────────────────────────────
        if 6 in cfg.run_tables:
            from evaluation.tables import table6_scalability
            t6_rows = table6_scalability.run(cfg)
            _save_csv(t6_rows, "table6_scalability.csv")
            all_rows.extend(t6_rows)

        # ── Table 7: Adaptive Cipher Selection ────────────────────────────────
        if 7 in cfg.run_tables:
            from evaluation.tables import table7_adaptive
            t7_rows = table7_adaptive.run(cfg)
            _save_csv(t7_rows, "table7_adaptive.csv")
            all_rows.extend(t7_rows)

        # ── Table 8: Live Stack Integration ───────────────────────────────────
        if 8 in cfg.run_tables:
            from evaluation.tables import table8_live_stack
            t8_rows = table8_live_stack.run(cfg)
            _save_csv(t8_rows, "table8_live_stack.csv")
            all_rows.extend(t8_rows)

        # ── Table 9: Topology Scalability (heavy — needs Mininet) ─────────────
        if 9 in cfg.run_tables:
            from evaluation.tables import table9_topo_scale
            t9_rows = table9_topo_scale.run(cfg)
            _save_csv(t9_rows, "table9_topo_scale.csv")
            all_rows.extend(t9_rows)

        # ── Table 10: DSA Comparison + Memory ─────────────────────────────────
        if 10 in cfg.run_tables:
            from evaluation.tables import table10_dsa_memory
            t10_rows = table10_dsa_memory.run(cfg)
            _save_csv(t10_rows, "table10_dsa_memory.csv")
            all_rows.extend(t10_rows)

    finally:
        # Stop the stack after all tables complete
        if stack._owned:
            print("\n  Stopping live stack ...")
            stack.stop()

    # ── Cross-table analysis ──────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("CROSS-TABLE ANALYSIS")
    print("=" * 72)

    # ANOVA
    if len(all_rows) > 0:
        try:
            anova_results = _run_anova_on_results(all_rows)
            if anova_results:
                _save_csv(anova_results, "analysis_anova.csv")
                print(f"\n  ANOVA: {len(anova_results)} comparisons")
                for r in anova_results:
                    sig = "✓ significant" if r.get("significant") else "✗ not significant"
                    print(f"    {r.get('operation', '?')}: F={r.get('f_statistic', 0):.2f}  "
                          f"p={r.get('p_value', 1):.4f}  {sig}")
        except ImportError:
            print("\n  ⚠ scipy/statsmodels not installed — skipping ANOVA")
        except Exception as e:
            print(f"\n  ⚠ ANOVA skipped: {e}")

    # TOPSIS
    try:
        topsis_results = _run_topsis(all_rows)
        if topsis_results:
            _save_csv(topsis_results, "analysis_topsis.csv")
            print(f"\n  TOPSIS ranking (handshake variants):")
            for r in topsis_results:
                print(f"    #{r['rank']}  {r['alternative']:<16}  score={r['score']:.4f}")
    except Exception as e:
        print(f"\n  ⚠ TOPSIS skipped: {e}")

    # ── Save combined results ─────────────────────────────────────────────
    if all_rows:
        combined_path = RESULTS_DIR / "all_results.json"
        with open(combined_path, "w") as f:
            json.dump(all_rows, f, indent=2, default=str)
        print(f"\n  Combined results: {combined_path}")

    # ── Generate figures ──────────────────────────────────────────────────
    if all_rows:
        try:
            from evaluation.figures import generate_all
            generate_all(all_rows)
        except ImportError as e:
            print(f"\n  ⚠ Figure generation skipped (missing dependency): {e}")
        except Exception as e:
            print(f"\n  ⚠ Figure generation error: {e}")

    # ── Generate analysis report ──────────────────────────────────────────
    elapsed = time.perf_counter() - t_start
    if all_rows:
        try:
            from evaluation.report import generate_report
            generate_report(all_rows, cfg, elapsed)
        except Exception as e:
            print(f"\n  ⚠ Report generation error: {e}")

    print(f"\n{'═' * 72}")
    print(f"  Evaluation complete in {elapsed:.1f}s")
    print(f"  Results:")
    print(f"    CSVs:    {RAW_DIR}/")
    print(f"    Figures: {RESULTS_DIR / 'figures'}/")
    print(f"    Report:  {RESULTS_DIR / 'analysis'}/")
    print(f"{'═' * 72}")


if __name__ == "__main__":
    main()
