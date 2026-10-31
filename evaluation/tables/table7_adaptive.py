"""
Table 7 — DSCP-Adaptive Cipher Selection & Proxy Overhead Analysis.

The key contribution comparison: why adaptive per-flow cipher selection
matters vs a static one-cipher-for-everything approach.

Inspired by:
  - CALIS (Springer 2025): per-flow AEAD selection in SDN-enabled IoT
  - Aquaman (Cisco Research 2025): transparent proxy overhead measurement
  - 6G Vehicular PQC (arXiv 2025): adaptive crypto switching with RL

Comparisons:
  1. Static AES-256-GCM for all traffic vs DSCP-adaptive selection
  2. Per-flow-class latency: VoIP vs Banking vs Bulk vs Real-time
  3. Mixed workload simulation: 100 flows with random DSCP, aggregate throughput
  4. Proxy relay overhead: with-proxy vs direct (no encryption, just TCP relay cost)
  5. Encryption overhead: proxy+encrypt vs proxy-only (isolates crypto cost)
  6. Adaptive switching latency: load change → cipher switch → first new frame
"""

from __future__ import annotations

import os
import random
import time
from typing import List

from evaluation.config import EvalConfig
from evaluation.stats import measure, describe, iqr_clean


# Representative DSCP traffic classes with their expected cipher
_FLOW_CLASSES = {
    "voip_ef":     {"dscp": 46, "label": "VoIP (EF)",       "expected_cipher": "ChaCha20-Poly1305"},
    "realtime_cs4": {"dscp": 32, "label": "Real-time (CS4)", "expected_cipher": "ChaCha20-Poly1305"},
    "banking_af11": {"dscp": 10, "label": "Banking (AF11)",  "expected_cipher": "AES-256-GCM"},
    "control_cs6":  {"dscp": 48, "label": "Control (CS6)",   "expected_cipher": "AES-256-GCM"},
    "video_af21":   {"dscp": 18, "label": "Video (AF21)",    "expected_cipher": "AES-128-GCM"},
    "bulk_be":      {"dscp": 0,  "label": "Bulk (BE)",       "expected_cipher": "AES-128-GCM"},
}

# Cipher overhead in microseconds per 64-byte frame (measured from Table 3)
# Will be measured live, but these are fallback estimates
_CIPHER_OVERHEAD_US = {
    "AES-256-GCM":       4.3,
    "AES-128-GCM":       4.3,
    "ChaCha20-Poly1305": 4.8,
}


def run(cfg: EvalConfig) -> List[dict]:
    from pqc_sdn.crypto.symmetric import AeadCipher
    from pqc_sdn.tls.session import SecureSession, SecurePacket, derive_directional_keys
    from pqc_sdn.tls.frames import encode_frame, decode_frame, packet_from_frame
    from pqc_sdn.policy.engine import PolicyEngine, PolicyMetrics
    from pqc_sdn.policy.dscp import DscpClass

    print("\n" + "=" * 72)
    print("TABLE 7 — DSCP-Adaptive vs Static Cipher Selection")
    print("=" * 72)

    rows = []
    engine = PolicyEngine()
    n = cfg.n_proxy
    of_frame = b"\x04\x0a\x00\x48" + b"\x00" * 68  # 72-byte PacketIn

    # ── 1. Per-flow-class latency comparison ──────────────────────────────
    print("\n  [1] Per-flow-class encrypt latency (adaptive cipher selection)")
    print(f"    {'Flow Class':<22} {'DSCP':>5}  {'Cipher':<22} {'Enc µs':>8} {'Dec µs':>8}")
    print("    " + "-" * 72)

    for flow_id, info in _FLOW_CLASSES.items():
        rec = engine.evaluate(PolicyMetrics(dscp_value=info["dscp"]))
        cipher_name = rec.algorithm

        key = AeadCipher.generate_key(cipher_name)
        cipher = AeadCipher(key, padding_block_size=256, algorithm=cipher_name)

        enc_stats = measure(lambda: cipher.encrypt(of_frame), n, unit_scale=1e6)

        # Decrypt
        packets = [cipher.encrypt(of_frame) for _ in range(n + 20)]
        idx = [0]
        def _dec():
            p = packets[idx[0]]
            cipher.decrypt(p.nonce, p.ciphertext)
            idx[0] += 1
        dec_stats = measure(_dec, n, unit_scale=1e6)

        print(f"    {info['label']:<22} {info['dscp']:>5}  {cipher_name:<22} "
              f"{enc_stats['mean']:>8.2f} {dec_stats['mean']:>8.2f}")

        rows.append({
            "table": 7, "comparison": "per_flow_class",
            "flow_class": flow_id, "flow_label": info["label"],
            "dscp": info["dscp"], "cipher": cipher_name,
            "enc_mean_us": enc_stats["mean"], "enc_p99_us": enc_stats["p99"],
            "dec_mean_us": dec_stats["mean"], "dec_p99_us": dec_stats["p99"],
            "enc_cov_pct": enc_stats["cov_pct"],
        })

    # ── 2. Static vs Adaptive aggregate throughput ────────────────────────
    print("\n  [2] Static AES-256-GCM vs DSCP-adaptive (mixed workload)")

    # Simulate mixed workload: random DSCP classes
    random.seed(42)
    mixed_dscps = [random.choice([0, 10, 18, 32, 46, 48]) for _ in range(2000)]

    # Pre-resolve cipher per DSCP class ONCE (correct model — policy is
    # evaluated at flow creation, not per encrypted frame)
    flow_cipher_map = {}
    for dscp in set(mixed_dscps):
        flow_cipher_map[dscp] = engine.evaluate(PolicyMetrics(dscp_value=dscp)).algorithm

    # Static mode: everything uses AES-256-GCM
    static_key = AeadCipher.generate_key("AES-256-GCM")
    static_cipher = AeadCipher(static_key, padding_block_size=256, algorithm="AES-256-GCM")
    for _ in range(50): static_cipher.encrypt(of_frame)  # warmup

    t0 = time.perf_counter()
    for _ in mixed_dscps:
        static_cipher.encrypt(of_frame)
    static_time = max(time.perf_counter() - t0, 1e-9)
    static_throughput = len(mixed_dscps) / static_time

    # Adaptive mode: cipher pre-resolved per DSCP, O(1) dict lookup per frame
    adaptive_ciphers = {}
    for algo in set(flow_cipher_map.values()):
        k = AeadCipher.generate_key(algo)
        adaptive_ciphers[algo] = AeadCipher(k, padding_block_size=256, algorithm=algo)
        for _ in range(20): adaptive_ciphers[algo].encrypt(of_frame)  # warmup

    t0 = time.perf_counter()
    for dscp in mixed_dscps:
        adaptive_ciphers[flow_cipher_map[dscp]].encrypt(of_frame)
    adaptive_time = max(time.perf_counter() - t0, 1e-9)
    adaptive_throughput = len(mixed_dscps) / adaptive_time

    improvement = (adaptive_throughput - static_throughput) / static_throughput * 100

    print(f"    Static  AES-256-GCM: {static_throughput:,.0f} frames/s")
    print(f"    Adaptive DSCP:       {adaptive_throughput:,.0f} frames/s")
    print(f"    Improvement: {improvement:+.1f}%  (cipher resolved once at flow creation)")

    rows.append({
        "table": 7, "comparison": "static_vs_adaptive",
        "mode": "static_aes256", "cipher": "AES-256-GCM",
        "total_frames": len(mixed_dscps),
        "total_time_ms": round(static_time * 1000, 2),
        "throughput_fps": round(static_throughput, 0),
    })
    rows.append({
        "table": 7, "comparison": "static_vs_adaptive",
        "mode": "dscp_adaptive", "cipher": "mixed",
        "total_frames": len(mixed_dscps),
        "total_time_ms": round(adaptive_time * 1000, 2),
        "throughput_fps": round(adaptive_throughput, 0),
        "improvement_pct": round(improvement, 1),
    })

    # ── 3. Cipher breakdown by DSCP class (what % of traffic uses what) ──
    print("\n  [3] DSCP traffic class distribution in mixed workload")
    cipher_counts = {}
    for dscp in mixed_dscps:
        rec = engine.evaluate(PolicyMetrics(dscp_value=dscp))
        cipher_counts[rec.algorithm] = cipher_counts.get(rec.algorithm, 0) + 1

    for algo, count in sorted(cipher_counts.items()):
        pct = 100.0 * count / len(mixed_dscps)
        print(f"    {algo:<22} {count:>4} flows ({pct:.0f}%)")
        rows.append({
            "table": 7, "comparison": "traffic_distribution",
            "cipher": algo, "flow_count": count,
            "percentage": round(pct, 1),
        })

    # ── 4. Proxy overhead isolation ───────────────────────────────────────
    print("\n  [4] Proxy overhead isolation (encrypt vs no-encrypt vs raw)")

    # Raw: just the OF frame bytes, no processing
    raw_samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        _ = of_frame  # no-op baseline
        raw_samples.append((time.perf_counter() - t0) * 1e6)
    raw_stats = describe(raw_samples)

    # Proxy relay (no encryption): frame parsing + forwarding overhead
    relay_samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        # Simulate proxy relay: parse OF header + copy
        _len = int.from_bytes(of_frame[2:4], "big")
        _copy = bytes(of_frame[:_len])
        relay_samples.append((time.perf_counter() - t0) * 1e6)
    relay_stats = describe(iqr_clean(relay_samples))

    # Proxy + encryption: full path
    enc_key = AeadCipher.generate_key("AES-256-GCM")
    enc_cipher = AeadCipher(enc_key, padding_block_size=256, algorithm="AES-256-GCM")
    encrypted_stats = measure(lambda: enc_cipher.encrypt(of_frame), n, unit_scale=1e6)

    # Calculate isolation
    relay_overhead = relay_stats["mean"] - raw_stats["mean"]
    crypto_overhead = encrypted_stats["mean"] - relay_stats["mean"]
    total_overhead = encrypted_stats["mean"] - raw_stats["mean"]

    print(f"    Raw (no proxy):         {raw_stats['mean']:.3f} µs")
    print(f"    Proxy relay (no crypto): {relay_stats['mean']:.3f} µs  (+{relay_overhead:.3f} µs relay overhead)")
    print(f"    Proxy + AES-256-GCM:    {encrypted_stats['mean']:.3f} µs  (+{crypto_overhead:.3f} µs crypto overhead)")
    print(f"    Total proxy overhead:    {total_overhead:.3f} µs")
    print(f"    Breakdown: {relay_overhead/total_overhead*100:.0f}% relay / {crypto_overhead/total_overhead*100:.0f}% crypto" if total_overhead > 0 else "")

    for label, stats, mode in [
        ("raw_baseline", raw_stats, "no_proxy"),
        ("proxy_relay", relay_stats, "proxy_no_crypto"),
        ("proxy_encrypted", encrypted_stats, "proxy_aes256"),
    ]:
        rows.append({
            "table": 7, "comparison": "proxy_overhead_isolation",
            "mode": mode, "mean_us": stats["mean"], "p99_us": stats["p99"],
        })

    rows.append({
        "table": 7, "comparison": "overhead_breakdown",
        "relay_overhead_us": round(relay_overhead, 3),
        "crypto_overhead_us": round(crypto_overhead, 3),
        "total_overhead_us": round(total_overhead, 3),
        "relay_pct": round(relay_overhead / total_overhead * 100, 1) if total_overhead > 0 else 0,
        "crypto_pct": round(crypto_overhead / total_overhead * 100, 1) if total_overhead > 0 else 0,
    })

    # ── 5. Latency-sensitive flow comparison ──────────────────────────────
    print("\n  [5] Latency-sensitive flow: ChaCha20 (adaptive) vs AES-256 (static)")

    # VoIP flow would get ChaCha20 under adaptive, AES-256 under static
    voip_key_c = AeadCipher.generate_key("ChaCha20-Poly1305")
    voip_chacha = AeadCipher(voip_key_c, padding_block_size=256, algorithm="ChaCha20-Poly1305")
    voip_key_a = AeadCipher.generate_key("AES-256-GCM")
    voip_aes256 = AeadCipher(voip_key_a, padding_block_size=256, algorithm="AES-256-GCM")

    voip_small = os.urandom(32)  # typical VoIP payload

    chacha_stats = measure(lambda: voip_chacha.encrypt(voip_small), n, unit_scale=1e6)
    aes256_stats = measure(lambda: voip_aes256.encrypt(voip_small), n, unit_scale=1e6)

    savings = aes256_stats["mean"] - chacha_stats["mean"]
    savings_pct = (savings / aes256_stats["mean"]) * 100 if aes256_stats["mean"] > 0 else 0

    print(f"    VoIP 32B payload:")
    print(f"      ChaCha20 (adaptive): {chacha_stats['mean']:.2f} µs")
    print(f"      AES-256  (static):   {aes256_stats['mean']:.2f} µs")
    print(f"      Savings:             {savings:.2f} µs ({savings_pct:.1f}%)")

    rows.append({
        "table": 7, "comparison": "voip_latency_savings",
        "cipher": "ChaCha20-Poly1305", "mode": "adaptive",
        "payload_bytes": 32, "mean_us": chacha_stats["mean"], "p99_us": chacha_stats["p99"],
    })
    rows.append({
        "table": 7, "comparison": "voip_latency_savings",
        "cipher": "AES-256-GCM", "mode": "static",
        "payload_bytes": 32, "mean_us": aes256_stats["mean"], "p99_us": aes256_stats["p99"],
        "savings_us": round(savings, 3), "savings_pct": round(savings_pct, 1),
    })

    # ── 6. Wire overhead comparison across ciphers ────────────────────────
    print("\n  [6] Wire overhead per cipher (same 72B OpenFlow frame)")

    for algo in ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]:
        k = AeadCipher.generate_key(algo)
        c = AeadCipher(k, padding_block_size=256, algorithm=algo)
        ct = c.encrypt(of_frame)
        pkt = SecurePacket(ciphertext=ct.ciphertext, nonce=ct.nonce,
                           sequence_number=0, timestamp=0, key_id="bench", epoch=0)
        wire = encode_frame(pkt)
        overhead = len(wire) - len(of_frame)

        print(f"    {algo:<22} plain={len(of_frame)}B → wire={len(wire)}B  overhead={overhead}B ({overhead/len(of_frame)*100:.0f}%)")

        rows.append({
            "table": 7, "comparison": "wire_overhead_per_cipher",
            "cipher": algo, "plain_bytes": len(of_frame),
            "wire_bytes": len(wire), "overhead_bytes": overhead,
            "overhead_pct": round(overhead / len(of_frame) * 100, 1),
        })

    # ── 6b. Multi-scenario concurrent workload benefit comparison ───────
    # Run 4 traffic class scenarios, each with concurrent background load.
    # For each: measure the foreground class p99 latency under:
    #   (a) static AES-256-GCM for everything
    #   (b) DSCP-adaptive (per-class cipher selection)
    # This proves the benefit across different real-world traffic types,
    # not just one VoIP example.
    print("\n  [6b] Multi-scenario benefit: adaptive vs static under concurrent load")

    import threading as _thr
    import statistics as _st

    n_fg = 500   # foreground samples
    n_bg = 500   # background concurrent encryptions

    # 4 scenarios: different foreground traffic types, each with bulk background
    scenarios = [
        {
            "name": "VoIP (EF)",
            "fg_payload": 32,       # small VoIP frame
            "fg_dscp_cipher": "ChaCha20-Poly1305",  # adaptive assigns this
            "bg_payload": 1024,     # bulk background
            "bg_dscp_cipher": "AES-128-GCM",         # adaptive assigns this
        },
        {
            "name": "Real-time video (CS4)",
            "fg_payload": 188,      # MPEG-TS packet
            "fg_dscp_cipher": "ChaCha20-Poly1305",
            "bg_payload": 1024,
            "bg_dscp_cipher": "AES-128-GCM",
        },
        {
            "name": "Banking (AF11)",
            "fg_payload": 256,      # transaction payload
            "fg_dscp_cipher": "AES-256-GCM",  # high-sec stays AES-256 in both modes
            "bg_payload": 64,       # control plane background
            "bg_dscp_cipher": "AES-128-GCM",
        },
        {
            "name": "Bulk transfer (BE)",
            "fg_payload": 1024,
            "fg_dscp_cipher": "AES-128-GCM",  # lighter cipher for bulk
            "bg_payload": 256,      # signalling background
            "bg_dscp_cipher": "AES-128-GCM",
        },
    ]

    print(f"    {'Scenario':<22} {'Mode':<14} {'Cipher':<14} "
          f"{'Mean µs':>8} {'p95 µs':>8} {'p99 µs':>8} {'Jitter':>8}")
    print(f"    {'-' * 84}")

    for scenario in scenarios:
        fg_data = os.urandom(scenario["fg_payload"])
        bg_data = os.urandom(scenario["bg_payload"])

        for mode_label, fg_cipher, bg_cipher in [
            ("static",   "AES-256-GCM", "AES-256-GCM"),
            ("adaptive", scenario["fg_dscp_cipher"], scenario["bg_dscp_cipher"]),
        ]:
            fg_key = AeadCipher.generate_key(fg_cipher)
            fg_c = AeadCipher(fg_key, padding_block_size=256, algorithm=fg_cipher)
            bg_key = AeadCipher.generate_key(bg_cipher)
            bg_c = AeadCipher(bg_key, padding_block_size=256, algorithm=bg_cipher)

            latencies = []
            bg_done = _thr.Event()

            def _bg(cipher=bg_c, data=bg_data):
                for _ in range(n_bg):
                    cipher.encrypt(data)
                bg_done.set()

            bg_thread = _thr.Thread(target=_bg, daemon=True)
            bg_thread.start()

            for _ in range(n_fg):
                t0 = time.perf_counter()
                fg_c.encrypt(fg_data)
                latencies.append((time.perf_counter() - t0) * 1e6)

            bg_done.wait(timeout=5)
            bg_thread.join(timeout=1)

            s = sorted(latencies)
            mean = _st.mean(latencies)
            p95 = s[int(len(s) * 0.95)]
            p99 = s[int(len(s) * 0.99)]
            jitter = _st.stdev(latencies) if len(latencies) > 1 else 0

            short_cipher = fg_cipher.replace("-Poly1305", "").replace("AES-", "")
            print(f"    {scenario['name']:<22} {mode_label:<14} {short_cipher:<14} "
                  f"{mean:>8.1f} {p95:>8.1f} {p99:>8.1f} {jitter:>8.1f}")

            rows.append({
                "table": 7, "comparison": "multi_scenario_benefit",
                "scenario": scenario["name"],
                "mode": mode_label,
                "fg_cipher": fg_cipher,
                "bg_cipher": bg_cipher,
                "fg_payload_bytes": scenario["fg_payload"],
                "fg_mean_us": round(mean, 2),
                "fg_p95_us": round(p95, 2),
                "fg_p99_us": round(p99, 2),
                "fg_jitter_us": round(jitter, 2),
            })

    # Summary: compute benefit per scenario
    print(f"\n    ── Adaptive benefit per scenario:")
    for scenario in scenarios:
        s_row = next((r for r in rows if r.get("comparison") == "multi_scenario_benefit"
                      and r.get("scenario") == scenario["name"] and r.get("mode") == "static"), None)
        a_row = next((r for r in rows if r.get("comparison") == "multi_scenario_benefit"
                      and r.get("scenario") == scenario["name"] and r.get("mode") == "adaptive"), None)
        if s_row and a_row:
            p99_red = (s_row["fg_p99_us"] - a_row["fg_p99_us"]) / s_row["fg_p99_us"] * 100 if s_row["fg_p99_us"] > 0 else 0
            jitter_red = (s_row["fg_jitter_us"] - a_row["fg_jitter_us"]) / s_row["fg_jitter_us"] * 100 if s_row["fg_jitter_us"] > 0 else 0
            print(f"    {scenario['name']:<22} p99: {p99_red:+.1f}%  jitter: {jitter_red:+.1f}%")

    # ── 7. Live file transfer through real proxy tunnel (DSCP-driven) ────
    # Sends 100KB through the ACTUAL sw_proxy→ctrl_proxy→Ryu encrypted
    # tunnel.  No in-process sessions — the real asyncio proxy pipeline
    # encrypts/decrypts every frame.
    from evaluation.live_stack_probe import (
        stack_is_up, live_file_transfer,
        scrape_prometheus_labels, scrape_prometheus_metric,
    )

    if stack_is_up():
        print("\n  [7] Live file transfer through real proxy tunnel (100KB) ...")
        print(f"    Path: client → sw_proxy:6634 (encrypt) → ctrl_proxy:6652 (decrypt) → Ryu:6653")

        result = live_file_transfer(file_size=102400, timeout=20.0)
        if result.get("success"):
            print(f"    Sent {result['bytes_sent']:,}B in {result['chunks_sent']} chunks  "
                  f"wire={result['wire_bytes']:,}B")
            print(f"    Echoes: {result['echoes_received']}/{result['chunks_sent']}  "
                  f"time={result['wall_ms']:.0f}ms  "
                  f"throughput={result['throughput_mbps']:.1f} Mbps")

            rows.append({
                "table": 7, "comparison": "live_file_transfer",
                "mode": "live_proxy_tunnel",
                "file_bytes": result["file_size"],
                "transfer_time_ms": result["wall_ms"],
                "throughput_mbps": result["throughput_mbps"],
                "chunks_sent": result["chunks_sent"],
                "echoes_received": result["echoes_received"],
            })
        else:
            print(f"    FAILED: {result.get('error', 'unknown')}")
    else:
        print("\n  [7] Live file transfer: SKIPPED (stack not running)")

    # ── 8. Live DSCP Verification (Prometheus pqc_flow_algorithm) ────────
    # Scrapes the running Ryu's Prometheus metrics to verify that the
    # correct cipher was assigned per DSCP class for active flows.
    if stack_is_up():
        print(f"\n  [8] Live DSCP Verification (Prometheus pqc_flow_algorithm)")

        flow_metrics = scrape_prometheus_labels("pqc_flow_algorithm")
        active_sessions = scrape_prometheus_metric("pqc_active_sessions")

        if flow_metrics:
            dscp_cipher_map = {
                "48": "AES-256-GCM", "56": "AES-256-GCM",
                "10": "AES-256-GCM", "12": "AES-256-GCM",
                "46": "ChaCha20-Poly1305", "32": "ChaCha20-Poly1305",
                "0": "AES-128-GCM", "18": "AES-128-GCM",
            }
            verified = 0
            mismatched = 0
            for fm in flow_metrics:
                dscp = fm["labels"].get("dscp", "")
                algo = fm["labels"].get("algorithm", "")
                dscp_name = fm["labels"].get("dscp_name", "")
                expected = dscp_cipher_map.get(dscp)
                if expected:
                    if algo == expected:
                        verified += 1
                        print(f"      ✓ DSCP={dscp} ({dscp_name}) → {algo}")
                    else:
                        mismatched += 1
                        print(f"      ✗ DSCP={dscp} ({dscp_name}) → {algo} (expected {expected})")

            print(f"    Sessions: {active_sessions or 'N/A'}  "
                  f"verified: {verified}  mismatched: {mismatched}")
            rows.append({
                "table": 7, "comparison": "live_dscp_verification",
                "mode": "live_stack", "flows_checked": len(flow_metrics),
                "flows_verified": verified, "flows_mismatched": mismatched,
                "active_sessions": active_sessions,
                "verdict": "PASS" if mismatched == 0 and verified > 0 else
                           "NO_FLOWS" if verified == 0 else "FAIL",
            })
        else:
            print(f"    No flow metrics — run Table 4 first to generate Mininet traffic")
            rows.append({"table": 7, "comparison": "live_dscp_verification",
                         "mode": "live_stack", "flows_checked": 0, "verdict": "NO_FLOWS"})
    else:
        print(f"\n  [8] Live DSCP Verification: SKIPPED (stack not running)")

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n  ── Summary")
    print(f"    DSCP-adaptive vs static: {improvement:+.1f}% throughput improvement on mixed workload")
    print(f"    VoIP latency savings: {savings_pct:.1f}% when using ChaCha20 vs forced AES-256")
    print(f"    Proxy overhead breakdown: relay={relay_overhead:.3f}µs + crypto={crypto_overhead:.3f}µs")

    return rows
