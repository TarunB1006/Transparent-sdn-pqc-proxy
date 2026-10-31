"""
Statistical helpers — IQR cleaning, ANOVA, TOPSIS, confidence intervals.

Methodology from:
  - pqc-iot-benchmark: IQR outlier removal, ANOVA + Tukey HSD, TOPSIS ranking
  - PQC-LEO: multi-run averaging, CoV reporting
"""

from __future__ import annotations

import math
import statistics
import time
import tracemalloc
from typing import List, Dict, Optional, Tuple, Callable

import numpy as np

from evaluation.config import (
    IQR_MULTIPLIER, SIGNIFICANCE_LEVEL, WARMUP_ITERATIONS, TOPSIS_WEIGHTS
)


# ── Core measurement ──────────────────────────────────────────────────────────

def measure(fn: Callable, n: int, unit_scale: float = 1e3,
            warmup: int = WARMUP_ITERATIONS, clean: bool = True) -> dict:
    """Run fn() n times with warmup, return full statistics.

    Args:
        fn: zero-arg callable to benchmark
        n: timed iterations
        unit_scale: 1e3 → ms, 1e6 → µs
        warmup: untimed warmup iterations
        clean: apply IQR outlier removal
    """
    for _ in range(warmup):
        fn()

    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * unit_scale)

    if clean and len(samples) > 10:
        samples = iqr_clean(samples)

    return describe(samples)


def measure_with_memory(fn: Callable, n: int, unit_scale: float = 1e3,
                        warmup: int = WARMUP_ITERATIONS) -> dict:
    """Like measure() but also tracks peak memory via tracemalloc."""
    for _ in range(warmup):
        fn()

    samples = []
    peak_memories = []

    for _ in range(n):
        tracemalloc.start()
        t0 = time.perf_counter()
        fn()
        elapsed = (time.perf_counter() - t0) * unit_scale
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        samples.append(elapsed)
        peak_memories.append(peak / 1024)  # bytes → KB

    samples = iqr_clean(samples) if len(samples) > 10 else samples

    result = describe(samples)
    result["peak_memory_kb"] = round(max(peak_memories), 2) if peak_memories else 0
    result["mean_memory_kb"] = round(float(np.mean(peak_memories)), 2) if peak_memories else 0
    return result


# ── Descriptive statistics ────────────────────────────────────────────────────

def describe(samples: List[float]) -> dict:
    """Full descriptive statistics for a list of measurements."""
    if not samples:
        return {}
    n = len(samples)
    sv = sorted(samples)
    mean = float(np.mean(samples))
    std = float(np.std(samples, ddof=1)) if n > 1 else 0.0
    ci_lo, ci_hi = confidence_interval_95(samples)
    return {
        "n": n,
        "mean": round(mean, 4),
        "std": round(std, 4),
        "min": round(sv[0], 4),
        "max": round(sv[-1], 4),
        "median": round(float(np.median(samples)), 4),
        "p95": round(sv[int(0.95 * n) - 1], 4) if n >= 20 else round(sv[-1], 4),
        "p99": round(sv[min(int(0.99 * n), n - 1)], 4) if n >= 100 else round(sv[-1], 4),
        "cov_pct": round(100.0 * std / mean, 2) if mean > 0 else 0.0,
        "ci95_lo": ci_lo,
        "ci95_hi": ci_hi,
    }


def confidence_interval_95(samples: List[float]) -> Tuple[float, float]:
    """95% confidence interval for the mean (z=1.96)."""
    n = len(samples)
    if n < 2:
        m = samples[0] if samples else 0.0
        return (m, m)
    mean = float(np.mean(samples))
    se = float(np.std(samples, ddof=1)) / math.sqrt(n)
    margin = 1.96 * se
    return (round(mean - margin, 4), round(mean + margin, 4))


# ── IQR outlier cleaning (from pqc-iot-benchmark) ────────────────────────────

def iqr_clean(samples: List[float], factor: float = IQR_MULTIPLIER) -> List[float]:
    """Remove outliers outside [Q1 - factor*IQR, Q3 + factor*IQR]."""
    if len(samples) < 4:
        return samples
    sv = sorted(samples)
    n = len(sv)
    q1 = sv[n // 4]
    q3 = sv[3 * n // 4]
    iqr = q3 - q1
    lo = q1 - factor * iqr
    hi = q3 + factor * iqr
    cleaned = [x for x in samples if lo <= x <= hi]
    return cleaned if cleaned else samples


# ── ANOVA + Tukey HSD (from pqc-iot-benchmark) ───────────────────────────────

def run_anova(groups: Dict[str, List[float]]) -> dict:
    """One-way ANOVA across named groups.

    Returns dict with f_statistic, p_value, significant (bool).
    """
    from scipy import stats as sp_stats

    group_lists = [v for v in groups.values() if len(v) > 1]
    if len(group_lists) < 2:
        return {"f_statistic": 0, "p_value": 1.0, "significant": False}

    f_stat, p_val = sp_stats.f_oneway(*group_lists)
    return {
        "f_statistic": round(float(f_stat), 4),
        "p_value": round(float(p_val), 6),
        "significant": float(p_val) < SIGNIFICANCE_LEVEL,
    }


def run_tukey_hsd(groups: Dict[str, List[float]]) -> List[dict]:
    """Tukey HSD pairwise comparison. Returns list of pairwise results."""
    from statsmodels.stats.multicomp import pairwise_tukeyhsd

    labels = []
    values = []
    for name, vals in groups.items():
        labels.extend([name] * len(vals))
        values.extend(vals)

    if len(set(labels)) < 2:
        return []

    result = pairwise_tukeyhsd(values, labels, alpha=SIGNIFICANCE_LEVEL)
    rows = []
    for i, (g1, g2, diff, padj, lo, hi, reject) in enumerate(
        zip(
            [r[0] for r in result._results_table.data[1:]],
            [r[1] for r in result._results_table.data[1:]],
            [r[2] for r in result._results_table.data[1:]],
            [r[3] for r in result._results_table.data[1:]],
            [r[4] for r in result._results_table.data[1:]],
            [r[5] for r in result._results_table.data[1:]],
            [r[6] for r in result._results_table.data[1:]],
        )
    ):
        rows.append({
            "group1": str(g1), "group2": str(g2),
            "mean_diff": round(float(diff), 4),
            "p_adj": round(float(padj), 6),
            "ci_lo": round(float(lo), 4), "ci_hi": round(float(hi), 4),
            "reject": bool(reject),
        })
    return rows


# ── TOPSIS ranking (from pqc-iot-benchmark) ───────────────────────────────────

def topsis_rank(
    alternatives: List[str],
    criteria: Dict[str, List[float]],
    weights: Optional[Dict[str, float]] = None,
    minimize: Optional[Dict[str, bool]] = None,
) -> List[dict]:
    """TOPSIS multi-criteria ranking.

    Args:
        alternatives: names of alternatives (e.g. algorithm variants)
        criteria: {criterion_name: [value_per_alternative]}
        weights: {criterion_name: weight}, defaults to TOPSIS_WEIGHTS
        minimize: {criterion_name: True if lower is better}, defaults all True
    """
    if weights is None:
        weights = TOPSIS_WEIGHTS
    if minimize is None:
        minimize = {k: True for k in criteria}

    n = len(alternatives)
    crit_names = list(criteria.keys())
    m = len(crit_names)

    # Build matrix
    matrix = np.zeros((n, m))
    for j, c in enumerate(crit_names):
        for i in range(n):
            matrix[i, j] = criteria[c][i]

    # Normalize (vector normalization)
    norms = np.sqrt((matrix ** 2).sum(axis=0))
    norms[norms == 0] = 1
    norm_matrix = matrix / norms

    # Weight
    w = np.array([weights.get(c, 1.0 / m) for c in crit_names])
    weighted = norm_matrix * w

    # Ideal best / worst
    ideal_best = np.zeros(m)
    ideal_worst = np.zeros(m)
    for j, c in enumerate(crit_names):
        if minimize.get(c, True):
            ideal_best[j] = weighted[:, j].min()
            ideal_worst[j] = weighted[:, j].max()
        else:
            ideal_best[j] = weighted[:, j].max()
            ideal_worst[j] = weighted[:, j].min()

    # Distances
    d_best = np.sqrt(((weighted - ideal_best) ** 2).sum(axis=1))
    d_worst = np.sqrt(((weighted - ideal_worst) ** 2).sum(axis=1))

    # Score
    scores = d_worst / (d_best + d_worst + 1e-10)

    # Rank
    ranked = sorted(range(n), key=lambda i: -scores[i])
    results = []
    for rank, idx in enumerate(ranked, 1):
        results.append({
            "rank": rank,
            "alternative": alternatives[idx],
            "score": round(float(scores[idx]), 4),
        })
    return results
