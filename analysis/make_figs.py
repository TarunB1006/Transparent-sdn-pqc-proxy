"""Paper figures from the final result files.

    python analysis/make_figs.py [--access] [cipher rtt arrival storm flood ...]

Writes PNGs into figures/ at the single-column (Springer) print width, or with
--access into figures/access/ at the two-column IEEE Access widths.
Error bars are 95% t-intervals over the per-repetition statistics, matching
the statistical methodology of the paper. Every figure is drawn at the width
at which the template includes it (Springer: text width 372 pt; IEEE Access:
text width 505 pt for figure*, column width 243 pt for the cipher figure), so
the fonts below are the sizes that appear in print and LaTeX never rescales
them. Every axis label carries its unit, and labels and panel titles are bold.
Three-panel figures use a 2x2 grid whose fourth cell holds the legend in the
narrow Springer layout and one row with the legend above in the wide IEEE
Access layout, so that the legend never covers data.
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analysis import ROOT, ci, load  # noqa: E402

RAW = ROOT / "evaluation" / "results" / "raw"

ACCESS = "--access" in sys.argv
if ACCESS:
    OUT = ROOT / "figures" / "access"
    W = 505.12 / 72.27    # \textwidth of ieeeaccess in inches
    CW = 242.67 / 72.27   # \columnwidth of ieeeaccess in inches
else:
    OUT = ROOT / "figures"
    W = CW = 372 / 72.27  # \textwidth of sn-jnl (single column) in inches

plt.rcParams.update({
    "font.family": "serif", "font.size": 9,
    "axes.labelsize": 9.5, "axes.labelweight": "bold",
    "axes.titlesize": 9.5, "axes.titleweight": "bold",
    "xtick.labelsize": 8.5, "ytick.labelsize": 8.5, "legend.fontsize": 8.5,
    "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.8,
    "xtick.major.width": 0.8, "ytick.major.width": 0.8,
    "grid.linestyle": "--", "grid.alpha": 0.4, "grid.linewidth": 0.6,
    "savefig.dpi": 600, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})

CFG_STYLE = {  # label, colour, marker
    "plain": ("Plaintext", "#757575", "o"),
    "tls_classical": ("TLS 1.3 classical", "#1E88E5", "s"),
    "pqtls_hybrid": ("TLS 1.3 hybrid", "#8E24AA", "^"),
    "pqtls_l5": ("TLS 1.3 post-quantum", "#F4511E", "D"),
    "pqtls_l5_chain": ("TLS 1.3 PQ + intermediate", "#6D4C41", "v"),
    "proposed": ("Proposed", "#2E7D32", "*"),
    "proposed_aes256": ("Proposed, AES-256-GCM only", "#3949AB", "P"),
    "proposed_chacha": ("Proposed, ChaCha20 only", "#F9A825", "X"),
}
CHANNEL_CFGS = ["plain", "tls_classical", "pqtls_hybrid", "pqtls_l5", "pqtls_l5_chain", "proposed"]


def _dodge(xs, i, n, frac=0.012):
    """Shift series i of n sideways so that equal values stay distinguishable."""
    span = (max(xs) - min(xs)) or 1
    return [x + (i - (n - 1) / 2) * frac * span for x in xs]


def _line(ax, xs, groups, cfg, **kw):
    label, col, mk = CFG_STYLE[cfg]
    m = [ci(g)[0] for g in groups]
    h = [ci(g)[1] for g in groups]
    ax.errorbar(xs, m, yerr=h, color=col, marker=mk, ms=7 if mk == "*" else 4.5,
                capsize=2.5, lw=1.4, elinewidth=0.9, capthick=0.9,
                label=kw.pop("label", label), **kw)


def _shared_legend(fig, axes, ncol):
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", bbox_to_anchor=(0.5, 1.0),
               ncol=ncol, frameon=False, columnspacing=1.2, handletextpad=0.4)


def _three_panels():
    """Three panels plus a legend slot: one row on the wide IEEE Access page,
    otherwise a 2x2 grid whose fourth cell carries the legend."""
    if ACCESS:
        fig, axes = plt.subplots(1, 3, figsize=(W, 2.45))
        return fig, tuple(axes), None
    fig, grid = plt.subplots(2, 2, figsize=(W, 4.6))
    grid[1, 1].axis("off")
    return fig, (grid[0, 0], grid[0, 1], grid[1, 0]), grid[1, 1]


def _legend_cell(fig, cell, axes):
    if cell is None:
        _shared_legend(fig, axes, ncol=6)
        return
    handles, labels = axes[0].get_legend_handles_labels()
    cell.legend(handles, labels, loc="center", frameon=False, fontsize=9,
                handlelength=2.4, labelspacing=0.9)


def cipher():
    rows = [r for r in csv.DictReader(open(RAW / "table3_channel.csv"))
            if r["operation"] == "roundtrip"]
    sizes = sorted({int(r["payload_bytes"]) for r in rows})
    fig, ax = plt.subplots(figsize=(CW, 2.3 if ACCESS else 2.8))
    # AES-256 and AES-128 nearly coincide, so AES-256 is drawn wide underneath
    # and AES-128 dashed on top, which keeps both visible.
    for algo, col, mk, lw, ls, ms in (("AES-256-GCM", "#F4511E", "o", 3.4, "-", 7.5),
                                      ("AES-128-GCM", "#1E88E5", "s", 1.4, "--", 4.5),
                                      ("ChaCha20-Poly1305", "#2E7D32", "^", 1.6, "-", 6)):
        v = [float(next(r["throughput_mbs"] for r in rows
                        if r["algorithm"] == algo and int(r["payload_bytes"]) == s)) for s in sizes]
        ax.plot(range(len(sizes)), v, marker=mk, ms=ms, color=col, lw=lw, ls=ls, label=algo,
                markeredgecolor="black", markeredgewidth=0.5)
    # Throughput spans two orders of magnitude, so a log axis keeps the small
    # payloads, where the ciphers trade places, as readable as the large ones.
    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
    ax.set_xticks(range(len(sizes)))
    ax.set_xticklabels([str(s) for s in sizes])
    ax.set_xlabel("Payload size (bytes)")
    ax.set_ylabel("Throughput (MB/s)")
    ax.grid(True, which="major")
    ax.legend(loc="upper left", frameon=False)
    fig.savefig(OUT / "fig_cipher_throughput.png")
    plt.close(fig)


def rtt():
    by = defaultdict(list)
    for r in load("rtt_loss"):
        by[(r["config"], r["rtt_ms"], r["loss_pct"])].append(r["ready_ms"])
    fig, axes, cell = _three_panels()
    a, b, c = axes
    rtts = sorted({k[1] for k in by if k[2] == 0})
    for cfg in CHANNEL_CFGS:   # continuous axis, so no sideways offset here
        _line(a, rtts, [[x["p50"] for x in by[(cfg, t, 0)]] for t in rtts], cfg)
    a.set_xlabel("Round-trip time (ms)")
    a.set_ylabel("Time to registration (ms)")
    a.set_title("(a) Median, no loss")

    # Loss panels at 50 ms RTT. The medians are flat, so lines with a small
    # sideways offset read well; the 95th percentiles cross and vary widely,
    # so they are drawn as grouped bars, which keeps each interval separate.
    losses = sorted({k[2] for k in by if k[1] == 50})
    for i, cfg in enumerate(CHANNEL_CFGS):
        xs = [l + (i - (len(CHANNEL_CFGS) - 1) / 2) * 0.07 for l in losses]
        _line(b, xs, [[x["p50"] for x in by[(cfg, 50, l)]] for l in losses], cfg)
    bw = 0.8 / len(CHANNEL_CFGS)
    for i, cfg in enumerate(CHANNEL_CFGS):
        _, col, _ = CFG_STYLE[cfg]
        stats = [ci([x["p95"] for x in by[(cfg, 50, l)]]) for l in losses]
        xs = [j + (i - (len(CHANNEL_CFGS) - 1) / 2) * bw for j in range(len(losses))]
        c.bar(xs, [s[0] for s in stats], bw, yerr=[s[1] for s in stats], color=col,
              edgecolor="black", linewidth=0.4, capsize=1.5,
              error_kw={"elinewidth": 0.8, "capthick": 0.8}, zorder=3)
    c.set_xticks(range(len(losses)))
    c.set_xticklabels([f"{l:g}" for l in losses])
    for ax, title in ((b, "(b) Median, 50 ms RTT"), (c, "(c) 95th percentile, 50 ms RTT")):
        ax.set_xlabel("Packet loss rate (%)")
        ax.set_ylabel("Time to registration (ms)")
        ax.set_title(title)
    b.set_xticks(losses)
    for ax in axes:
        ax.grid(True, axis="y" if ax is c else "both")
    _legend_cell(fig, cell, axes)
    fig.tight_layout(w_pad=1.5)
    fig.savefig(OUT / "fig_rtt_loss.png")
    plt.close(fig)


def arrival():
    by = defaultdict(list)
    for r in load("arrival_emu"):
        by[(r["config"], r["rate"])].append(r)
    rates = sorted({k[1] for k in by})
    fig, axes, cell = _three_panels()
    a, b, c = axes
    for i, cfg in enumerate(CHANNEL_CFGS):
        xs = _dodge(rates, i, len(CHANNEL_CFGS))
        _line(a, xs, [[x["ready_ms"]["p50"] for x in by[(cfg, r)]] for r in rates], cfg)
        _line(b, xs, [[x["ready_ms"]["p95"] for x in by[(cfg, r)]] for r in rates], cfg)
        _line(c, xs, [[x["ctrl_cpu_pct"] for x in by[(cfg, r)]] for r in rates], cfg)
    for ax, title, ylab in ((a, "(a) Median", "Time to registration (ms)"),
                            (b, "(b) 95th percentile", "Time to registration (ms)"),
                            (c, "(c) Controller-side CPU", "CPU utilization (%)")):
        ax.set_xticks(rates)
        ax.set_xlabel("Arrival rate (switches/s)")
        ax.set_ylabel(ylab)
        ax.set_title(title)
        ax.grid(True)
    _legend_cell(fig, cell, axes)
    fig.tight_layout(w_pad=1.5)
    fig.savefig(OUT / "fig_arrival.png")
    plt.close(fig)


def storm():
    emu, ovs = defaultdict(list), defaultdict(list)
    for r in load("storm_emu"):
        emu[(r["config"], r["n_switches"])].append(r)
    for r in load("storm"):
        ovs[(r["config"], r["n_switches"])].append(r)
    sizes = sorted({k[1] for k in emu})
    fig, axes, cell = _three_panels()
    a, b, c = axes
    for i, cfg in enumerate(CHANNEL_CFGS):
        xs = _dodge(sizes, i, len(CHANNEL_CFGS))
        _line(a, xs, [[x["all_ready_ms"] for x in emu[(cfg, n)]] for n in sizes], cfg)
        _line(b, xs, [[x["ctrl_cpu_s"] for x in ovs[(cfg, n)]] for n in sizes], cfg)
        if cfg != "plain":   # plaintext has no switch-side process
            _line(c, xs, [[x["sw_cpu_s"] for x in ovs[(cfg, n)]] for n in sizes], cfg)
    for ax, title, ylab in ((a, "(a) All switches registered", "Time (ms)"),
                            (b, "(b) Controller-side CPU time", "CPU time (s)"),
                            (c, "(c) Switch-side CPU time", "CPU time (s)")):
        ax.set_xticks(sizes)
        ax.set_xlabel("Reconnecting switches")
        ax.set_ylabel(ylab)
        ax.set_title(title)
        ax.grid(True)
    _legend_cell(fig, cell, axes)
    fig.tight_layout(w_pad=1.5)
    fig.savefig(OUT / "fig_storm.png")
    plt.close(fig)


def flood():
    by = defaultdict(list)
    for r in load("flood"):
        by[(None, r["no_aesni"], r["config"], r["rate"])].append(r["latency_ms"]["p50"])
    for r in load("flood_constrained"):
        by[(r["sw_cpu_quota_pct"], r["no_aesni"], r["config"], r["rate"])].append(r["latency_ms"]["p50"])
    panels = [((None, False), "(a) Full CPU, AES-NI on"),
              ((None, True), "(b) Full CPU, AES-NI off"),
              ((25, True), "(c) 25% of a core, AES-NI off"),
              ((10, True), "(d) 10% of a core, AES-NI off")]
    cfgs = ["plain", "pqtls_l5", "proposed", "proposed_aes256", "proposed_chacha"]
    # The wide IEEE Access page fits all four panels in one row, which saves
    # about half a page; the narrow Springer page needs a 2x2 grid.
    if ACCESS:
        fig, grid = plt.subplots(1, 4, figsize=(W, 2.55), sharey=True)
        panels = [(k, t.replace(", ", ",\n", 1)) for k, t in panels]
    else:
        fig, grid = plt.subplots(2, 2, figsize=(W, 4.9), sharey=True)
    axes = grid.ravel()
    for ax, ((quota, noaes), title) in zip(axes, panels):
        for i, cfg in enumerate(cfgs):
            rates = sorted({k[3] for k in by if k[:3] == (quota, noaes, cfg)})
            if not rates:
                continue
            xs = _dodge(rates, i, len(cfgs), frac=0.02)
            extra = {"label": "Proposed, DSCP-driven"} if cfg == "proposed" else {}
            _line(ax, xs, [by[(quota, noaes, cfg, r)] for r in rates], cfg, **extra)
        ax.set_yscale("log")
        ax.set_ylim(2, 6000)   # leaves room for the 2.5 s point in panel (d)
        ax.set_xticks(sorted({k[3] for k in by if k[:2] == (quota, noaes)}))
        ax.set_xlabel("Offered rate\n(new flows/s)" if ACCESS else "Offered rate (new flows/s)")
        ax.set_title(title, fontsize=9)
        ax.grid(True, which="major")
    # One label for both rows; per-row labels would collide between the rows.
    if ACCESS:
        axes[0].set_ylabel("Median flow-setup\nlatency (ms)")
    else:
        fig.supylabel("Median flow-setup latency (ms)", fontsize=9.5, fontweight="bold")
    # Plaintext only appears in panel (a); take the legend from there.
    _shared_legend(fig, axes, ncol=3 if ACCESS else 2)
    fig.tight_layout(w_pad=1.2)
    fig.savefig(OUT / "fig_flood.png")
    plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    names = [a for a in sys.argv[1:] if a != "--access"]
    for name in names or ["cipher", "rtt", "arrival", "storm", "flood"]:
        globals()[name]()
        print("written", name)
