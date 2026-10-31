#!/usr/bin/env python3
"""
symmetric_cipher_comparison.py — Compare all three AEAD ciphers used by the
DSCP-adaptive symmetric layer: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305.

Produces throughput (MB/s) and latency (µs) at each payload size, plus a
summary row showing the DSCP classes that select each cipher.

Run:
    PYTHONPATH=src python3 benchmarks/symmetric_cipher_comparison.py
"""

import csv
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqc_sdn.crypto.symmetric import AeadCipher

ALGORITHMS = ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]
PAYLOAD_SIZES = [64, 256, 512, 1024, 4096, 16384, 65536]
N = 2000

DSCP_USE = {
    "AES-256-GCM":       "CS6/CS7/HIGH_SEC/AF11-13 (control plane, bank/DB)",
    "AES-128-GCM":       "BE/AF2x/AF3x/CS3/CS5 (video, signalling, bulk)",
    "ChaCha20-Poly1305": "EF/CS4/AF4x (VoIP, real-time — no AES-NI needed)",
}


def bench_cipher(algorithm: str, size: int) -> dict:
    key = AeadCipher.generate_key(algorithm)
    cipher = AeadCipher(key, padding_block_size=0, algorithm=algorithm)
    payload = os.urandom(size)

    enc_times = []
    for _ in range(N):
        t0 = time.perf_counter()
        ct = cipher.encrypt(payload)
        enc_times.append((time.perf_counter() - t0) * 1e6)

    ct = cipher.encrypt(payload)
    dec_times = []
    for _ in range(N):
        t0 = time.perf_counter()
        cipher.decrypt(ct.nonce, ct.ciphertext)
        dec_times.append((time.perf_counter() - t0) * 1e6)

    mb = size / (1024 * 1024)
    enc_mean = statistics.mean(enc_times)
    dec_mean = statistics.mean(dec_times)

    return {
        "algorithm":          algorithm,
        "payload_bytes":      size,
        "enc_mean_us":        round(enc_mean, 3),
        "enc_p95_us":         round(sorted(enc_times)[int(0.95 * N)], 3),
        "enc_throughput_mbs": round(mb / (enc_mean / 1e6), 2),
        "dec_mean_us":        round(dec_mean, 3),
        "dec_p95_us":         round(sorted(dec_times)[int(0.95 * N)], 3),
        "dec_throughput_mbs": round(mb / (dec_mean / 1e6), 2),
    }


rows = []
for algo in ALGORITHMS:
    print(f"\n── {algo}  (DSCP classes: {DSCP_USE[algo]})")
    print(f"  {'Size':>7}  {'Enc µs':>8} {'p95':>7}  {'Enc MB/s':>10}  "
          f"{'Dec µs':>8} {'p95':>7}  {'Dec MB/s':>10}")
    print("  " + "-" * 70)
    for size in PAYLOAD_SIZES:
        r = bench_cipher(algo, size)
        rows.append(r)
        label = f"{size}B" if size < 1024 else f"{size // 1024}KB"
        print(f"  {label:>7}  {r['enc_mean_us']:>8.3f} {r['enc_p95_us']:>7.3f}"
              f"  {r['enc_throughput_mbs']:>10.2f}"
              f"  {r['dec_mean_us']:>8.3f} {r['dec_p95_us']:>7.3f}"
              f"  {r['dec_throughput_mbs']:>10.2f}")

# Summary: which cipher wins at 64B (control-plane typical message size)
print("\n── Summary at 64B payload (typical OpenFlow control message)")
print(f"  {'Algorithm':<22}  {'Enc µs':>8}  {'Dec µs':>8}  {'Enc MB/s':>10}")
print("  " + "-" * 56)
for r in [r for r in rows if r["payload_bytes"] == 64]:
    print(f"  {r['algorithm']:<22}  {r['enc_mean_us']:>8.3f}  {r['dec_mean_us']:>8.3f}"
          f"  {r['enc_throughput_mbs']:>10.2f}")

out = os.path.join(os.path.dirname(__file__), "..", "results", "symmetric_cipher_comparison.csv")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
print(f"\nSaved → {os.path.relpath(out)}")
