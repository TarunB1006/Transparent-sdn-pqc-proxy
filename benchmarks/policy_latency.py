#!/usr/bin/env python3
"""
PolicyEngine decision latency benchmark.
Measures evaluate() across every defined DSCP class (n=1000 each).
"""

import csv
import statistics
import time

from pqc_sdn.policy.dscp import DscpClass
from pqc_sdn.policy.engine import PolicyEngine, PolicyMetrics

N = 1000
engine = PolicyEngine()


def measure(dscp: DscpClass) -> dict:
    samples = []
    for _ in range(N):
        t0 = time.perf_counter()
        engine.evaluate(PolicyMetrics(dscp_value=dscp.value))
        samples.append((time.perf_counter() - t0) * 1e6)  # microseconds

    rec = engine.evaluate(PolicyMetrics(dscp_value=dscp.value))
    return {
        "dscp_class": dscp.name,
        "dscp_value": dscp.value,
        "algorithm": rec.algorithm,
        "flow_type": rec.flow_type.value,
        "mean_us": round(statistics.mean(samples), 4),
        "median_us": round(statistics.median(samples), 4),
        "std_us": round(statistics.stdev(samples), 4),
        "min_us": round(min(samples), 4),
        "max_us": round(max(samples), 4),
    }


rows = [measure(d) for d in DscpClass]

# --- Print table ---
print(f"\n{'DSCP':<8} {'Value':>5}  {'Algorithm':<14} {'Flow Type':<20} {'Mean (µs)':>10} {'±Std':>8} {'Min':>8} {'Max':>8}")
print("-" * 90)
for r in rows:
    print(f"{r['dscp_class']:<8} {r['dscp_value']:>5}  {r['algorithm']:<14} {r['flow_type']:<20} {r['mean_us']:>10.4f} {r['std_us']:>8.4f} {r['min_us']:>8.4f} {r['max_us']:>8.4f}")

means = [r["mean_us"] for r in rows]
print(f"\nOverall  mean={statistics.mean(means):.4f} µs  min={min(means):.4f} µs  max={max(means):.4f} µs  (n={N} per class)")

# --- CSV ---
with open("policy_latency.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
print("Saved → policy_latency.csv")
