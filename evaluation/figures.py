"""
IEEE-ready figure generation for PQC-SDN evaluation.

Produces publication-quality PNG figures (300 DPI) from evaluation CSVs.
Inspired by pqc-iot-benchmark's generate_figures.py — adapted for our
three-way comparison (Classical vs Standard PQC vs Our Implementation).

Figures:
  1. Grouped bar — KEM micro-ops (keygen/encap/decap) per variant
  2. Grouped bar — Handshake latency (classical TLS vs PQC variants)
  3. Box plot — Handshake scalability (latency distribution at each concurrency)
  4. Stacked bar — Wire overhead breakdown per cipher + payload size
  5. Grouped bar — Symmetric cipher throughput comparison
  6. Radar/spider — TOPSIS multi-criteria profile per KEM variant
  7. Heatmap — DSCP class → cipher mapping with policy evaluation latency
  8. Horizontal bar — Security attack results (detection rates)
  9. Line plot — Scalability: throughput vs concurrency per variant
 10. Bar — Three-way overhead comparison (the headline figure)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

from evaluation.config import FIGURES_DIR

# ── Style ─────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "font.size": 10,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.figsize": (8, 5),
    "axes.grid": True,
    "grid.alpha": 0.3,
})

COLORS = {
    "A_classical": "#2196F3",
    "C_pqc_sdn": "#4CAF50",
    "TLS1.3-P256": "#2196F3",
    "ML-KEM-512": "#4CAF50",
    "ML-KEM-768": "#FF9800",
    "ML-KEM-1024": "#F44336",
    "AES-256-GCM": "#3F51B5",
    "AES-128-GCM": "#009688",
    "ChaCha20-Poly1305": "#FF5722",
}


def _save(fig, name: str):
    path = FIGURES_DIR / f"{name}.png"
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"    → {path.name}")


# ── Figure generators ─────────────────────────────────────────────────────────

def fig01_kem_micro_ops(rows: list):
    """Three-panel bar: KEM keygen/encap/decap — 3-way classical vs liboqs vs wrapper."""
    kem_rows = [r for r in rows if r.get("table") == 1 and "kem_" in r.get("operation", "")]
    if not kem_rows:
        return

    variants = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    ops = ["kem_keygen", "kem_encap", "kem_decap"]
    op_labels = {"kem_keygen": "KeyGen", "kem_encap": "Encap", "kem_decap": "Decap"}
    modes = [("A_classical", "Classical (X25519)"),
             ("B_liboqs", "liboqs (C-level)"),
             ("C_pqc_sdn", "PQC-SDN Wrapper")]

    fig, axes = plt.subplots(1, 3, figsize=(16, 5), sharey=True)
    x = np.arange(len(variants))
    width = 0.25

    for ax, op in zip(axes, ops):
        for i, (mode_key, mode_label) in enumerate(modes):
            vals = []
            for v in variants:
                val = next((r["mean"] for r in kem_rows
                            if r["mode"] == mode_key and r["algorithm"] == v
                            and r["operation"] == op), 0)
                # Classical X25519 has one value per op — replicate across columns
                if mode_key == "A_classical" and val == 0:
                    val = next((r["mean"] for r in kem_rows
                                if r["mode"] == mode_key and r["operation"] == op), 0)
                vals.append(val)

            bars = ax.bar(x + (i - 1) * width, vals, width,
                          label=mode_label if ax == axes[0] else None,
                          color=COLORS.get(mode_key, "#999"), alpha=0.9)
            for bar, v in zip(bars, vals):
                if v > 0:
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                            f"{v:.0f}", ha="center", va="bottom", fontsize=7)

        ax.set_title(op_labels[op], fontsize=11)
        ax.set_xticks(x)
        ax.set_xticklabels([v.replace("ML-KEM-", "") for v in variants])
        ax.set_xlabel("Security Level")
        ax.grid(axis="y", alpha=0.3)
        if ax == axes[0]:
            ax.set_ylabel("Latency (µs)")
            ax.legend(fontsize=8)

    fig.suptitle("Fig 1: KEM Micro-Operations — Classical vs liboqs vs PQC-SDN Wrapper", y=1.02)
    _save(fig, "fig01_kem_micro_ops")


def fig02_handshake_comparison(rows: list):
    """Grouped bar: handshake latency — TLS baseline vs each PQC variant."""
    hs_rows = [r for r in rows if r.get("table") == 2 and r.get("concurrency") == 1
               and r.get("mode") in ("A_classical_tls13", "C_pqc_sdn")]
    if not hs_rows:
        return

    labels = [r["algorithm"] for r in hs_rows]
    means = [r["mean"] for r in hs_rows]
    stds = [r["std"] for r in hs_rows]
    colors = [COLORS.get(r["algorithm"], COLORS.get(r["mode"], "#999")) for r in hs_rows]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, means, yerr=stds, capsize=5, color=colors, edgecolor="white", linewidth=0.5)

    # Add overhead % labels
    baseline = means[0] if means else 1
    for bar, m in zip(bars[1:], means[1:]):
        overhead = (m - baseline) / baseline * 100
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                f"+{overhead:.0f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_ylabel("Handshake Latency (ms)")
    ax.set_title("Fig 2: Handshake Protocol — Classical TLS 1.3 vs PQC-SDN")
    _save(fig, "fig02_handshake_comparison")


def fig03_scalability_throughput(rows: list):
    """Line plot: throughput (hs/s) vs concurrency per KEM variant."""
    scale_rows = [r for r in rows if r.get("table") == 6 and r.get("mode") == "scalability"]
    if not scale_rows:
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    variants = sorted(set(r["algorithm"] for r in scale_rows))

    for v in variants:
        vr = sorted([r for r in scale_rows if r["algorithm"] == v], key=lambda r: r["concurrency"])
        concs = [r["concurrency"] for r in vr]
        tputs = [r["throughput_hps"] for r in vr]
        ax.plot(concs, tputs, "o-", label=v, color=COLORS.get(v, "#999"), linewidth=2, markersize=6)

    ax.set_xlabel("Concurrent Handshakes")
    ax.set_ylabel("Throughput (handshakes/s)")
    ax.set_title("Fig 3: Handshake Scalability — Throughput vs Concurrency")
    ax.legend()
    _save(fig, "fig03_scalability_throughput")


def fig04_scalability_latency(rows: list):
    """Line plot: mean latency vs concurrency per variant (degradation curves)."""
    scale_rows = [r for r in rows if r.get("table") == 6 and r.get("mode") == "scalability"]
    if not scale_rows:
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    variants = sorted(set(r["algorithm"] for r in scale_rows))

    for v in variants:
        vr = sorted([r for r in scale_rows if r["algorithm"] == v], key=lambda r: r["concurrency"])
        concs = [r["concurrency"] for r in vr]
        means = [r["mean"] for r in vr]
        p95s = [r.get("p95", r["mean"]) for r in vr]
        ax.plot(concs, means, "o-", label=f"{v} (mean)", color=COLORS.get(v, "#999"), linewidth=2)
        ax.plot(concs, p95s, "s--", label=f"{v} (p95)", color=COLORS.get(v, "#999"), linewidth=1, alpha=0.6)

    ax.set_xlabel("Concurrent Handshakes")
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Fig 4: Handshake Scalability — Latency Degradation")
    ax.legend(fontsize=8)
    _save(fig, "fig04_scalability_latency")


def fig05_cipher_throughput(rows: list):
    """Grouped bar: cipher throughput (MB/s) per payload size per algorithm."""
    ch_rows = [r for r in rows if r.get("table") == 3 and r.get("operation") == "roundtrip"]
    if not ch_rows:
        return

    algos = sorted(set(r["algorithm"] for r in ch_rows))
    payloads = sorted(set(r["payload_bytes"] for r in ch_rows))

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(payloads))
    n_algos = len(algos)
    width = 0.8 / n_algos

    for i, algo in enumerate(algos):
        vals = [next((r["throughput_mbs"] for r in ch_rows
                       if r["algorithm"] == algo and r["payload_bytes"] == p), 0)
                for p in payloads]
        ax.bar(x + i * width - (n_algos - 1) * width / 2, vals, width,
               label=algo, color=COLORS.get(algo, "#999"))

    ax.set_xticks(x)
    ax.set_xticklabels([f"{p}B" if p < 1024 else f"{p//1024}KB" for p in payloads])
    ax.set_xlabel("Payload Size")
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title("Fig 5: Symmetric Cipher Throughput Comparison")
    ax.legend()
    _save(fig, "fig05_cipher_throughput")


def fig06_wire_overhead(rows: list):
    """Stacked bar: wire overhead breakdown (nonce + tag + padding) per payload."""
    ch_rows = [r for r in rows if r.get("table") == 3
               and r.get("operation") == "roundtrip"
               and r.get("algorithm") == "AES-256-GCM"]
    if not ch_rows:
        return

    payloads = [r["payload_bytes"] for r in ch_rows]
    wire = [r["wire_bytes"] for r in ch_rows]
    overhead = [r["overhead_bytes"] for r in ch_rows]
    overhead_pct = [r["overhead_pct"] for r in ch_rows]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Left: absolute bytes
    labels = [f"{p}B" if p < 1024 else f"{p//1024}KB" for p in payloads]
    ax1.bar(labels, payloads, label="Payload", color="#4CAF50")
    ax1.bar(labels, overhead, bottom=payloads, label="PQC Overhead", color="#F44336", alpha=0.8)
    ax1.set_ylabel("Bytes")
    ax1.set_title("Wire Frame Size Breakdown")
    ax1.legend()

    # Right: overhead percentage
    ax2.bar(labels, overhead_pct, color="#FF9800")
    ax2.set_ylabel("Overhead (%)")
    ax2.set_title("PQC Overhead as % of Payload")
    ax2.axhline(y=50, color="red", linestyle="--", alpha=0.5, label="50% threshold")
    ax2.legend()

    fig.suptitle("Fig 6: PQC Proxy Wire Overhead (AES-256-GCM)", y=1.02)
    _save(fig, "fig06_wire_overhead")


def fig07_security_scorecard(rows: list):
    """Horizontal bar: security attack results with pass/fail coloring and tier grouping."""
    sec_rows = [r for r in rows if r.get("table") == 5 and r.get("verdict") != "SKIPPED"]
    if not sec_rows:
        return

    attacks = [r["attack"] for r in sec_rows]
    rates = [r.get("detection_rate_pct", 0) for r in sec_rows]
    verdicts = [r.get("verdict", "?") for r in sec_rows]
    tiers = [r.get("tier", "5A") for r in sec_rows]
    colors = []
    for v in verdicts:
        if v == "PASS":
            colors.append("#4CAF50")
        elif v in ("PARTIAL", "WARN", "INFO"):
            colors.append("#FF9800")
        else:
            colors.append("#F44336")

    fig, ax = plt.subplots(figsize=(10, max(5, len(attacks) * 0.45)))
    y = np.arange(len(attacks))
    bars = ax.barh(y, rates, color=colors, edgecolor="white", height=0.6)

    ax.set_yticks(y)
    labels = []
    for a, t in zip(attacks, tiers):
        prefix = "[Crypto] " if t == "5A" else "[Network] "
        labels.append(prefix + a.replace("_", " ").title())
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Detection Rate (%)")
    ax.set_xlim(0, 115)
    ax.set_title("Fig 7: Security Attack Detection Results")
    ax.axvline(x=100, color="green", linestyle="--", alpha=0.4)

    for bar, rate, verdict in zip(bars, rates, verdicts):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                f"{rate:.0f}% {verdict}", va="center", fontsize=8, fontweight="bold")

    _save(fig, "fig07_security_scorecard")


def fig08_dscp_heatmap(rows: list):
    """Heatmap: DSCP class → cipher mapping with evaluation latency."""
    policy_rows = [r for r in rows if r.get("table") == 3 and r.get("operation") == "policy_eval"]
    if not policy_rows:
        return

    ciphers = sorted(set(r["algorithm"] for r in policy_rows))
    dscp_classes = [r["dscp_class"] for r in policy_rows]
    latencies = [r["mean_us"] for r in policy_rows]
    assigned = [r["algorithm"] for r in policy_rows]

    # Build matrix: rows=DSCP classes, columns=ciphers, values=1 if assigned
    cipher_idx = {c: i for i, c in enumerate(ciphers)}
    matrix = np.zeros((len(dscp_classes), len(ciphers)))
    for i, (dc, algo) in enumerate(zip(dscp_classes, assigned)):
        if algo in cipher_idx:
            matrix[i, cipher_idx[algo]] = 1

    fig, ax = plt.subplots(figsize=(8, 8))
    im = ax.imshow(matrix, cmap="YlGn", aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(np.arange(len(ciphers)))
    ax.set_xticklabels(ciphers, rotation=30, ha="right")
    ax.set_yticks(np.arange(len(dscp_classes)))
    ax.set_yticklabels(dscp_classes, fontsize=8)
    ax.set_xlabel("Assigned Cipher")
    ax.set_ylabel("DSCP Class")
    ax.set_title("Fig 8: DSCP → Cipher Policy Mapping")

    # Annotate with latency
    for i in range(len(dscp_classes)):
        for j in range(len(ciphers)):
            if matrix[i, j] > 0:
                ax.text(j, i, f"{latencies[i]:.1f}µs", ha="center", va="center", fontsize=7)

    _save(fig, "fig08_dscp_heatmap")


def fig09_memory_profile(rows: list):
    """Dual-panel: (left) per-session memory scaling from T10, (right) DSA algorithm comparison."""
    # Session scaling from T10
    mem_rows = [r for r in rows if r.get("table") == 10
                and r.get("section", "").startswith("10B") and r.get("n_sessions", 0) > 0]
    # DSA comparison from T10
    dsa_rows = [r for r in rows if r.get("table") == 10
                and r.get("section", "").startswith("10A") and r.get("sign_us", 0) > 0]

    # Fall back to T1 per-operation memory if T10 unavailable
    if not mem_rows and not dsa_rows:
        t1_mem = [r for r in rows if r.get("table") == 1
                  and r.get("mode") == "C_pqc_sdn"
                  and r.get("peak_memory_kb", 0) > 0]
        if not t1_mem:
            return
        labels = [f"{r['algorithm']}\n{r['operation'].replace('kem_','').replace('dsa_','')}" for r in t1_mem]
        mems = [r["peak_memory_kb"] for r in t1_mem]
        fig, ax = plt.subplots(figsize=(10, 5))
        colors_list = [COLORS.get(r["algorithm"], "#999") for r in t1_mem]
        ax.bar(range(len(labels)), mems, color=colors_list)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
        ax.set_ylabel("Peak Memory (KB)")
        ax.set_title("Fig 9: Peak Memory Usage per PQC Operation")
        _save(fig, "fig09_memory_profile")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Left panel: session scaling (memory per session converges to constant)
    if mem_rows:
        sessions = [r["n_sessions"] for r in mem_rows]
        per_session = [r["per_session_kb"] for r in mem_rows]
        peak = [r["peak_memory_kb"] for r in mem_rows]

        ax1.plot(sessions, per_session, "o-", color="#E64A19", linewidth=2, markersize=8,
                 label="Per-session (KB)")
        for s, p in zip(sessions, per_session):
            ax1.annotate(f"{p:.2f}", (s, p), textcoords="offset points",
                         xytext=(0, 10), ha="center", fontsize=8)

        ax1b = ax1.twinx()
        ax1b.bar(sessions, peak, width=[s*0.15 for s in sessions], alpha=0.2,
                 color="#1565C0", label="Total peak (KB)")
        ax1b.set_ylabel("Total Peak Memory (KB)", color="#1565C0")

        ax1.set_xlabel("Concurrent Sessions")
        ax1.set_ylabel("Memory per Session (KB)")
        ax1.set_title("Session Memory Scaling")
        ax1.axhline(y=per_session[-1], color="#E64A19", linestyle="--", alpha=0.4)
        ax1.annotate(f"Converges → {per_session[-1]:.2f} KB/session",
                     xy=(sessions[-1], per_session[-1]),
                     xytext=(-80, -25), textcoords="offset points",
                     fontsize=9, fontweight="bold", color="#E64A19")
        ax1.legend(loc="upper left", fontsize=8)
        ax1.grid(axis="y", alpha=0.3)

    # Right panel: DSA algorithm comparison (sign + verify latency)
    if dsa_rows:
        algos = [r["algorithm"] for r in dsa_rows]
        signs = [r["sign_us"] for r in dsa_rows]
        verifies = [r["verify_us"] for r in dsa_rows]
        x = np.arange(len(algos))
        w = 0.35

        bars1 = ax2.bar(x - w/2, signs, w, label="Sign", color="#F44336")
        bars2 = ax2.bar(x + w/2, verifies, w, label="Verify", color="#4CAF50")
        for bar, v in zip(bars1, signs):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10,
                     f"{v:.0f}", ha="center", va="bottom", fontsize=8)
        for bar, v in zip(bars2, verifies):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10,
                     f"{v:.0f}", ha="center", va="bottom", fontsize=8)

        ax2.set_xticks(x)
        ax2.set_xticklabels(algos, fontsize=8)
        ax2.set_ylabel("Latency (µs)")
        ax2.set_title("DSA Algorithm Comparison")
        ax2.legend()
        ax2.grid(axis="y", alpha=0.3)

        # Highlight quantum-safe
        for i, r in enumerate(dsa_rows):
            if r.get("quantum_safe"):
                ax2.get_xticklabels()[i].set_fontweight("bold")

    fig.suptitle("Fig 9: Memory Scaling & DSA Algorithm Comparison", y=1.02)
    _save(fig, "fig09_memory_profile")


def fig10_three_way_headline(rows: list):
    """The headline figure: three-way overhead comparison."""
    hs_rows = [r for r in rows if r.get("table") == 2 and r.get("concurrency") == 1]
    if not hs_rows:
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    labels = []
    means = []
    stds = []
    bar_colors = []

    for r in hs_rows:
        algo = r["algorithm"]
        mode = r["mode"]
        if mode == "A_classical_tls13":
            labels.append("Classical\nTLS 1.3")
            bar_colors.append("#2196F3")
        else:
            labels.append(f"PQC-SDN\n{algo}")
            bar_colors.append(COLORS.get(algo, "#4CAF50"))
        means.append(r["mean"])
        stds.append(r["std"])

    bars = ax.bar(labels, means, yerr=stds, capsize=5, color=bar_colors,
                  edgecolor="white", linewidth=0.5, width=0.6)

    # Add value labels
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f"{m:.2f}ms", ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_ylabel("Handshake Latency (ms)")
    ax.set_title("Fig 10: Three-Way Comparison — Handshake Protocol Overhead")
    ax.axhline(y=means[0], color="#2196F3", linestyle="--", alpha=0.4, label="Classical baseline")
    ax.legend()
    _save(fig, "fig10_three_way_headline")


def fig11_static_vs_adaptive(rows: list):
    """Dual-panel: (left) throughput comparison, (right) per-cipher breakdown showing WHY adaptive is near-identical on AES-NI."""
    comp_rows = [r for r in rows if r.get("table") == 7
                 and r.get("comparison") == "static_vs_adaptive"]
    if not comp_rows:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Left panel: throughput comparison
    labels = []
    vals = []
    colors = []
    for r in comp_rows:
        mode = r.get("mode", "")
        if "static" in mode:
            labels.append("Static\nAES-256-GCM")
            colors.append("#F44336")
        else:
            labels.append("DSCP\nAdaptive")
            colors.append("#4CAF50")
        vals.append(r.get("throughput_fps", 0))

    bars = ax1.bar(labels, vals, color=colors, width=0.5, edgecolor="white")
    for bar, v in zip(bars, vals):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 200,
                f"{v:,.0f}", ha="center", va="bottom", fontsize=11, fontweight="bold")

    if len(vals) >= 2 and vals[0] > 0:
        diff_pct = (vals[1] - vals[0]) / vals[0] * 100
        ax1.set_title(f"Throughput: {diff_pct:+.1f}% (within noise)")
    else:
        ax1.set_title("Throughput Comparison")
    ax1.set_ylabel("Throughput (frames/s)")
    ax1.grid(axis="y", alpha=0.3)

    # Right panel: per-flow-class encrypt latency (why they're similar)
    flow_rows = [r for r in rows if r.get("table") == 7
                 and r.get("comparison") == "per_flow_class"]
    if flow_rows:
        fl = [r["flow_label"] for r in flow_rows]
        enc = [r["enc_mean_us"] for r in flow_rows]
        ciphers = [r["cipher"] for r in flow_rows]
        fc = [COLORS.get(c, "#999") for c in ciphers]

        bars2 = ax2.bar(fl, enc, color=fc, edgecolor="white")
        for bar, v, c in zip(bars2, enc, ciphers):
            short = c.replace("-Poly1305", "").replace("AES-", "AES").replace("-GCM", "")
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                     f"{v:.2f}µs\n({short})", ha="center", va="bottom", fontsize=7)

        ax2.set_ylabel("Encrypt Latency (µs)")
        ax2.set_title("Per-Flow Cipher Latency (AES-NI equalizes all)")
        ax2.set_ylim(0, max(enc) * 1.15 if enc else 12)
        plt.sca(ax2)
        plt.xticks(rotation=20, ha="right", fontsize=8)
        ax2.grid(axis="y", alpha=0.3)

    fig.suptitle("Fig 11: DSCP-Adaptive Cipher Selection — Overhead & Per-Flow Breakdown", y=1.02)
    _save(fig, "fig11_static_vs_adaptive")


def fig12_per_flow_class(rows: list):
    """Skipped — merged into fig11 dual-panel."""
    pass


def fig13_proxy_overhead_breakdown(rows: list):
    """Dual-panel: (left) proxy overhead breakdown relay vs crypto, (right) live file transfer throughput."""
    breakdown = [r for r in rows if r.get("table") == 7
                 and r.get("comparison") == "overhead_breakdown"]
    ft_rows = [r for r in rows if r.get("table") == 7 and r.get("comparison") == "live_file_transfer"]

    if not breakdown and not ft_rows:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    # Left: overhead breakdown
    if breakdown:
        b = breakdown[0]
        relay = b.get("relay_overhead_us", 0)
        crypto = b.get("crypto_overhead_us", 0)
        total = relay + crypto

        ax1.bar(["Proxy\nOverhead"], [relay], label=f"TCP Relay ({b.get('relay_pct', 0):.0f}%)",
                color="#FF9800", width=0.4)
        ax1.bar(["Proxy\nOverhead"], [crypto], bottom=[relay],
                label=f"Encryption ({b.get('crypto_pct', 0):.0f}%)", color="#3F51B5", width=0.4)
        ax1.set_ylabel("Overhead (µs)")
        ax1.set_title(f"Per-Packet Overhead: {total:.1f} µs total")
        ax1.legend(fontsize=9)
        ax1.text(0, total + 0.2, f"{total:.2f} µs", ha="center", fontsize=11, fontweight="bold")
    else:
        ax1.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax1.transAxes)

    # Right: live file transfer
    if ft_rows:
        tp = ft_rows[0].get("throughput_mbps", 0)
        chunks = ft_rows[0].get("chunks_sent", 0)
        echoes = ft_rows[0].get("echoes_received", 0)
        wall = ft_rows[0].get("transfer_time_ms", 0)

        bar = ax2.bar(["Live Proxy\nTunnel"], [tp], color="#4CAF50", width=0.4, edgecolor="white")
        ax2.text(0, tp + 1, f"{tp:.1f} Mbps", ha="center", fontsize=12, fontweight="bold")
        ax2.set_ylabel("Throughput (Mbps)")
        ax2.set_title(f"File Transfer: {chunks} chunks, {wall:.0f}ms")
        ax2.grid(axis="y", alpha=0.3)
    else:
        ax2.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax2.transAxes)

    fig.suptitle("Fig 12: Proxy Per-Packet Overhead & Live Tunnel Throughput", y=1.02)
    _save(fig, "fig12_proxy_and_tunnel")


def fig14_dscp_file_transfer(rows: list):
    """Skipped — merged into fig12 dual-panel."""
    pass


def fig15_live_stack_summary(rows: list):
    """Horizontal bar: live stack integration tests with quantitative metrics."""
    live_rows = [r for r in rows if r.get("table") == 8]
    if not live_rows:
        return

    tests = [r.get("test", "?") for r in live_rows]
    verdicts = [r.get("verdict", "?") for r in live_rows]

    # Build quantitative labels
    details = []
    for r in live_rows:
        t = r.get("test", "")
        if "handshake" in t:
            details.append(f"{r.get('handshake_ms', '?')}ms ML-KEM")
        elif "tunnel" in t:
            details.append(f"{r.get('messages_sent', '?')} msgs, {r.get('wire_bytes', '?')}B")
        elif "file" in t:
            details.append(f"{r.get('wire_bytes', '?')}B in {r.get('tunnel_time_ms', '?')}ms")
        elif "prometheus" in t:
            details.append(f"sessions={r.get('active_sessions', '?')}")
        elif "replay" in t:
            details.append("replay rejected ✓")
        else:
            details.append("")

    colors = ["#4CAF50" if v == "PASS" else "#F44336" for v in verdicts]

    fig, ax = plt.subplots(figsize=(10, max(4, len(tests) * 0.6)))
    y = np.arange(len(tests))
    bars = ax.barh(y, [100 if v == "PASS" else 0 for v in verdicts],
                   color=colors, edgecolor="white", height=0.5)

    ax.set_yticks(y)
    ax.set_yticklabels([t.replace("_", " ").title() for t in tests], fontsize=9)
    ax.set_xlim(0, 130)
    ax.set_xlabel("Pass (%)")
    ax.set_title("Fig 13: Live Stack Integration — Real Proxy End-to-End Tests")

    for bar, verdict, detail in zip(bars, verdicts, details):
        label = f"{verdict}  {detail}" if detail else verdict
        ax.text(bar.get_width() + 2, bar.get_y() + bar.get_height()/2,
                label, va="center", fontsize=9, fontweight="bold",
                color="#4CAF50" if verdict == "PASS" else "#F44336")

    _save(fig, "fig13_live_stack_summary")


def fig16_multi_scenario_benefit(rows: list):
    """Grouped bar: adaptive vs static p99 latency across 4 traffic scenarios."""
    ms_rows = [r for r in rows if r.get("table") == 7
               and r.get("comparison") == "multi_scenario_benefit"]
    if len(ms_rows) < 2:
        return

    scenarios = []
    seen = set()
    for r in ms_rows:
        s = r.get("scenario", "")
        if s and s not in seen:
            scenarios.append(s)
            seen.add(s)

    static_p99 = []
    adaptive_p99 = []
    for s in scenarios:
        sv = next((r["fg_p99_us"] for r in ms_rows
                    if r.get("scenario") == s and r.get("mode") == "static"), 0)
        av = next((r["fg_p99_us"] for r in ms_rows
                    if r.get("scenario") == s and r.get("mode") == "adaptive"), 0)
        static_p99.append(sv)
        adaptive_p99.append(av)

    x = np.arange(len(scenarios))
    w = 0.35

    fig, ax = plt.subplots(figsize=(10, 5))
    bars1 = ax.bar(x - w/2, static_p99, w, color="#F44336", label="Static AES-256-GCM")
    bars2 = ax.bar(x + w/2, adaptive_p99, w, color="#4CAF50", label="DSCP-Adaptive")

    for b, v in zip(bars1, static_p99):
        if v > 0:
            ax.text(b.get_x() + b.get_width()/2, b.get_height() + 1,
                    f"{v:.0f}", ha="center", va="bottom", fontsize=9)
    for b, v in zip(bars2, adaptive_p99):
        if v > 0:
            ax.text(b.get_x() + b.get_width()/2, b.get_height() + 1,
                    f"{v:.0f}", ha="center", va="bottom", fontsize=9)

    # Annotate % reduction
    for i in range(len(scenarios)):
        if static_p99[i] > 0 and adaptive_p99[i] > 0:
            red = (static_p99[i] - adaptive_p99[i]) / static_p99[i] * 100
            y = max(static_p99[i], adaptive_p99[i]) + 5
            ax.annotate(f"{red:+.0f}%", xy=(x[i], y), ha="center",
                        fontsize=10, fontweight="bold",
                        color="#2E7D32" if red > 0 else "#B71C1C")

    ax.set_xlabel("Traffic Scenario")
    ax.set_ylabel("p99 Latency (µs) Under Concurrent Load")
    ax.set_title("Fig 16: Adaptive vs Static — p99 Latency Across 4 Traffic Scenarios")
    ax.set_xticks(x)
    ax.set_xticklabels(scenarios, rotation=15, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    _save(fig, "fig16_multi_scenario_benefit")


def fig17_live_vs_inprocess(rows: list):
    """Bar: live stack handshake vs in-process handshake latency."""
    inproc = [r for r in rows if r.get("table") == 2
              and r.get("mode") == "C_pqc_sdn" and r.get("concurrency") == 1]
    live = [r for r in rows if r.get("table") == 2
            and r.get("mode") == "D_live_stack"]
    classical = [r for r in rows if r.get("table") == 2
                 and r.get("mode") == "A_classical_tls13"]

    if not inproc or not live:
        return

    labels = []
    values = []
    colors_list = []

    if classical:
        labels.append("Classical\nTLS 1.3")
        values.append(classical[0]["mean"])
        colors_list.append("#9E9E9E")

    labels.append("PQC In-Process\n(no network)")
    values.append(inproc[0]["mean"])
    colors_list.append("#2196F3")

    labels.append("PQC Live Stack\n(sw_proxy→ctrl_proxy→Ryu)")
    values.append(live[0]["mean"])
    colors_list.append("#4CAF50")

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, values, color=colors_list, width=0.5, edgecolor="white")

    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                f"{v:.2f}ms", ha="center", va="bottom", fontsize=11, fontweight="bold")

    ax.set_ylabel("Handshake Latency (ms)")
    ax.set_title("Fig 17: Handshake Latency — Classical vs PQC In-Process vs Live Stack")
    ax.grid(axis="y", alpha=0.3)
    _save(fig, "fig17_live_vs_inprocess")


def fig18_topo_scalability(rows: list):
    """Line plot: ping latency and throughput vs topology size (k)."""
    topo_rows = [r for r in rows if r.get("table") == 9 and r.get("test") == "topo_scale"
                 and "error" not in r]
    if not topo_rows:
        return

    ks = [r["k"] for r in topo_rows]
    hosts = [r["hosts"] for r in topo_rows]
    pings = [r.get("ping_avg_ms", 0) for r in topo_rows]
    throughputs = [r.get("throughput_mbps", 0) for r in topo_rows]
    converge = [r.get("converge_time_s", 0) for r in topo_rows]

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))

    # Ping vs topology size
    ax1.plot(hosts, pings, "o-", color="#F44336", linewidth=2, markersize=8)
    ax1.set_xlabel("Number of Hosts")
    ax1.set_ylabel("Ping RTT (ms)")
    ax1.set_title("Latency vs Scale")
    for x, y, k in zip(hosts, pings, ks):
        ax1.annotate(f"k={k}", (x, y), textcoords="offset points", xytext=(5, 10), fontsize=8)

    # Throughput vs topology size
    ax2.plot(hosts, throughputs, "s-", color="#4CAF50", linewidth=2, markersize=8)
    ax2.set_xlabel("Number of Hosts")
    ax2.set_ylabel("Throughput (Mbps)")
    ax2.set_title("Throughput vs Scale")
    for x, y, k in zip(hosts, throughputs, ks):
        ax2.annotate(f"k={k}", (x, y), textcoords="offset points", xytext=(5, 10), fontsize=8)

    # Convergence time vs topology size
    ax3.bar([f"k={k}\n{h} hosts" for k, h in zip(ks, hosts)], converge,
            color="#2196F3", edgecolor="white")
    ax3.set_ylabel("Convergence Time (s)")
    ax3.set_title("Topology Convergence")

    fig.suptitle("Fig 15: PQC-SDN Performance vs Topology Scale", y=1.02)
    _save(fig, "fig15_topo_scalability")


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_all(all_rows: list):
    """Generate all figures from evaluation results."""
    print("\n" + "=" * 72)
    print("FIGURE GENERATION")
    print("=" * 72)
    print(f"  Output: {FIGURES_DIR}/\n")

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    generators = [
        ("Fig 01: KEM Micro-Ops (3-way)", fig01_kem_micro_ops),
        ("Fig 02: Handshake Comparison", fig02_handshake_comparison),
        ("Fig 03: Scalability Throughput", fig03_scalability_throughput),
        ("Fig 04: Scalability Latency", fig04_scalability_latency),
        ("Fig 05: Cipher Throughput", fig05_cipher_throughput),
        ("Fig 06: Wire Overhead", fig06_wire_overhead),
        ("Fig 07: Security Scorecard", fig07_security_scorecard),
        ("Fig 08: DSCP Heatmap", fig08_dscp_heatmap),
        ("Fig 09: Memory & DSA Comparison", fig09_memory_profile),
        ("Fig 10: Three-Way Headline", fig10_three_way_headline),
        ("Fig 11: Adaptive Cipher Selection", fig11_static_vs_adaptive),
        ("Fig 12: Proxy Overhead & Tunnel", fig13_proxy_overhead_breakdown),
        ("Fig 13: Live Stack Integration", fig15_live_stack_summary),
        ("Fig 14: Multi-Scenario p99 Benefit", fig16_multi_scenario_benefit),
        ("Fig 15: Live vs In-Process Handshake", fig17_live_vs_inprocess),
        ("Fig 16: Topology Scalability", fig18_topo_scalability),
    ]

    generated = 0
    for name, fn in generators:
        try:
            fn(all_rows)
            generated += 1
        except Exception as e:
            print(f"    ⚠ {name} skipped: {e}")

    print(f"\n  Generated {generated}/{len(generators)} figures")
