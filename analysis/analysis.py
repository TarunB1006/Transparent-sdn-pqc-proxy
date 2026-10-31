"""Summaries of the final Mininet results for the paper (prints, no writes).

Per-repetition statistics are aggregated as the mean over repetitions with a
95% t-interval, as described in the paper's statistical methodology.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy import stats

ROOT = Path(__file__).resolve().parents[1]
MN = ROOT / "evaluation" / "results" / "mininet"
CFGS = ["plain", "tls_classical", "pqtls_hybrid", "pqtls_l5", "pqtls_l5_chain", "proposed"]


def load(name):
    return json.loads((MN / f"{name}.json").read_text())


def ci(vals):
    a = np.asarray([v for v in vals if v is not None], float)
    if len(a) < 2:
        return float(a.mean()) if len(a) else float("nan"), 0.0, len(a)
    h = stats.t.ppf(0.975, len(a) - 1) * a.std(ddof=1) / np.sqrt(len(a))
    return float(a.mean()), float(h), len(a)


def fmt(vals, d=1):
    m, h, n = ci(vals)
    return f"{m:.{d}f}±{h:.{d}f}"


def wire():
    by = defaultdict(list)
    for r in load("wire"):
        by[r["config"]].append((r["bytes_up"], r["bytes_down"]))
    print("== wire (bytes up / down: min..max over reps)")
    for c in CFGS:
        u = [x[0] for x in by[c]]; d = [x[1] for x in by[c]]
        print(f"  {c:16s} up {np.median(u):.0f} [{min(u)}..{max(u)}]  down {np.median(d):.0f} [{min(d)}..{max(d)}]  n={len(u)}")


def rtt():
    by = defaultdict(lambda: defaultdict(list))
    for r in load("rtt_loss"):
        by[(r["rtt_ms"], r["loss_pct"])][r["config"]].append(r["ready_ms"])
    print("== rtt_loss: mean of per-rep p50 / p95 (ms, 95% CI)")
    for cell in sorted(by):
        print(f"  rtt={cell[0]:>3} loss={cell[1]}%")
        for c in CFGS:
            rs = by[cell][c]
            print(f"    {c:16s} p50 {fmt([x['p50'] for x in rs])}  p95 {fmt([x['p95'] for x in rs])}")




def holm(pvals):
    """Holm-Bonferroni adjusted p-values, same order as the input."""
    order = np.argsort(pvals)
    adj = np.empty(len(pvals))
    run = 0.0
    for rank, i in enumerate(order):
        run = max(run, min(1.0, (len(pvals) - rank) * pvals[i]))
        adj[i] = run
    return adj


def welch(a, b):
    return stats.ttest_ind(a, b, equal_var=False).pvalue


def rtt_tests():
    by = defaultdict(list)
    for r in load("rtt_loss"):
        by[(r["config"], r["rtt_ms"], r["loss_pct"])].append(r["ready_ms"]["p50"])
    cells = sorted({(k[1], k[2]) for k in by})
    names, ps, diffs = [], [], []
    for cell in cells:
        for other in ("tls_classical", "pqtls_hybrid", "pqtls_l5", "pqtls_l5_chain"):
            a, b = by[("proposed",) + cell], by[(other,) + cell]
            names.append(f"rtt={cell[0]} loss={cell[1]} proposed vs {other}")
            ps.append(welch(a, b)); diffs.append(np.mean(a) - np.mean(b))
    print("== rtt Welch on per-rep medians, Holm over", len(ps), "comparisons")
    for n, d, p in zip(names, diffs, holm(np.array(ps))):
        print(f"  {n:55s} diff {d:+7.1f} ms  p_holm {p:.2g}")




def storm():
    ovs, emu = defaultdict(list), defaultdict(list)
    for r in load("storm"):
        ovs[(r["n_switches"], r["config"])].append(r)
    for r in load("storm_emu"):
        emu[(r["n_switches"], r["config"])].append(r)
    print("== storm: all-ready (instrumented, ms) | ctrl-side CPU (OVS, s) | ctrl CPU (instr, s) | OVS all-ready")
    for n in (20, 45, 80, 125):
        for c in CFGS:
            e, o = emu[(n, c)], ovs[(n, c)]
            print(f"  N={n:>3} {c:16s} ready {fmt([x['all_ready_ms'] for x in e])}  "
                  f"cpu {fmt([x['ctrl_cpu_s'] for x in o], 2)}  cpu_emu {fmt([x['ctrl_cpu_s'] for x in e], 2)}  "
                  f"ovs_ready {fmt([x['all_ready_ms'] for x in o])}  fail {sum(x['failures'] for x in e + o)}")
    print("  proposed vs pqtls_l5 CPU reduction (OVS):")
    for n in (20, 45, 80, 125):
        a = [x["ctrl_cpu_s"] for x in ovs[(n, "proposed")]]
        b = [x["ctrl_cpu_s"] for x in ovs[(n, "pqtls_l5")]]
        print(f"    N={n}: {100 * (1 - np.mean(a) / np.mean(b)):.1f}%  p={welch(a, b):.2g}")


def arrival():
    ovs, emu = defaultdict(list), defaultdict(list)
    for r in load("arrival"):
        ovs[(r["rate"], r["config"])].append(r)
    for r in load("arrival_emu"):
        emu[(r["rate"], r["config"])].append(r)
    print("== arrival: instrumented p50 / p95 (ms) | cpu% instr | OVS cpu% | OVS achieved rate")
    for rate in sorted({k[0] for k in emu}):
        for c in CFGS:
            e, o = emu[(rate, c)], ovs.get((rate, c), [])
            line = (f"  R={rate:>3} {c:16s} p50 {fmt([x['ready_ms']['p50'] for x in e])}  "
                    f"p95 {fmt([x['ready_ms']['p95'] for x in e])}  cpu_e {fmt([x['ctrl_cpu_pct'] for x in e])}")
            if o:
                line += (f"  cpu_ovs {fmt([x['ctrl_cpu_pct'] for x in o])}"
                         f"  rate {fmt([x['achieved_rate'] for x in o])}")
            print(line)


def flood(name="flood"):
    by = defaultdict(list)
    for r in load(name):
        by[(r.get("sw_cpu_quota_pct"), r["rate"], r["no_aesni"], r["config"])].append(r)
    print(f"== {name}: delivered/s | p50 | p99 (ms) | ctrl cpu%")
    for k in sorted(by, key=lambda k: (str(k[0]), k[1], k[2], k[3])):
        rs = by[k]
        print(f"  quota={k[0]} R={k[1]:>4} aesni={'off' if k[2] else 'on '} {k[3]:16s} "
              f"deliv {fmt([x['delivered_per_s'] for x in rs])}  p50 {fmt([x['latency_ms'].get('p50') for x in rs], 2)}  "
              f"p99 {fmt([x['latency_ms'].get('p99') for x in rs], 1)}  cpu {fmt([x['ctrl_cpu_pct'] for x in rs])}  n={len(rs)}")


def tost(a, b, margin):
    """Two one-sided Welch tests; returns the larger one-sided p-value."""
    a, b = np.asarray(a, float), np.asarray(b, float)
    d = a.mean() - b.mean()
    va, vb = a.var(ddof=1) / len(a), b.var(ddof=1) / len(b)
    se = np.sqrt(va + vb)
    df = (va + vb) ** 2 / (va ** 2 / (len(a) - 1) + vb ** 2 / (len(b) - 1))
    p_lo = 1 - stats.t.cdf((d + margin) / se, df)
    p_hi = stats.t.cdf((d - margin) / se, df)
    return max(p_lo, p_hi)


def flood_tests(name="flood", margin=0.25):
    by = defaultdict(list)
    for r in load(name):
        by[(r.get("sw_cpu_quota_pct"), r["rate"], r["no_aesni"], r["config"])].append(r["latency_ms"]["p50"])
    names, ps, tp, ds = [], [], [], []
    for k in sorted(by, key=str):
        if k[3] != "proposed":
            continue
        for other in ("proposed_aes256", "proposed_chacha"):
            kk = k[:3] + (other,)
            if kk not in by:
                continue
            names.append(f"quota={k[0]} R={k[1]} aesni={'off' if k[2] else 'on'} adaptive vs {other}")
            ps.append(welch(by[k], by[kk])); tp.append(tost(by[k], by[kk], margin))
            ds.append(np.mean(by[k]) - np.mean(by[kk]))
    print(f"== {name} p50: Welch (Holm over {len(ps)}) and TOST margin {margin} ms")
    for n, d, p, t in zip(names, ds, holm(np.array(ps)), tp):
        print(f"  {n:58s} diff {d:+.3f}  p_holm {p:.2g}  tost_p {t:.2g}")


TOPO_MODES = ["direct", "tls_classical", "pqc_proxy", "pqc_uniform", "pqc_uniform_chacha"]


def topo(margins={"ping_avg_ms": 0.05, "throughput_mbps": 1.0}):
    rows = json.loads((ROOT / "evaluation/results/topo_final/topo_comparison.json").read_text())
    by = defaultdict(list)
    for r in rows:
        by[(r["k"], r["mode"])].append(r)
    print("== topo: converge s | ping ms | tput Mb/s | cpu avg/peak % | mem MB (mean±CI, n)")
    for k in (4, 6, 8, 10):
        for m in TOPO_MODES:
            rs = by[(k, m)]
            g = lambda f: [x.get(f) for x in rs if x.get(f) not in (None, -1)]
            print(f"  k={k:>2} {m:20s} conv {fmt(g('converge_time_s'), 2)}  ping {fmt(g('ping_avg_ms'), 3)}  "
                  f"tput {fmt(g('throughput_mbps'), 2)}  cpu {fmt(g('cpu_avg_pct'))}/{fmt(g('cpu_peak_pct'))}  "
                  f"mem {fmt(g('mem_peak_mb'))}  n={len(rs)} conv_ok={sum(bool(x.get('converged')) for x in rs)}")
    for f, mg in margins.items():
        names, ps, tp = [], [], []
        for k in (4, 6, 8, 10):
            for m in ("pqc_proxy", "pqc_uniform", "pqc_uniform_chacha"):
                for base in ("direct", "tls_classical"):
                    a = [x[f] for x in by[(k, m)]]; b = [x[f] for x in by[(k, base)]]
                    names.append(f"k={k} {m} vs {base}"); ps.append(welch(a, b)); tp.append(tost(a, b, mg))
        adj = holm(np.array(ps))
        print(f"== {f}: Welch (Holm over {len(ps)}), TOST margin {mg}")
        print(f"  significant after Holm: {sum(adj < 0.05)}   equivalent (TOST p<0.05): {sum(np.array(tp) < 0.05)}/{len(tp)}")
        for n, p, t in zip(names, adj, tp):
            if p < 0.05 or t >= 0.05:
                print(f"    {n:40s} p_holm {p:.2g}  tost_p {t:.2g}")


if __name__ == "__main__":
    for name in sys.argv[1:]:
        globals()[name]()
