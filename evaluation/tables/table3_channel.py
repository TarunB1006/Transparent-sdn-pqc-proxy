"""
Table 3 — Data Channel / Proxy Overhead.

Compares: No encryption vs Static AES-256-GCM vs DSCP-adaptive cipher selection.
Measures: per-frame encrypt/decrypt latency, wire overhead, throughput, all 3 ciphers.
Also includes DSCP policy evaluation latency.

Methodology: bench_proxy.py logic (fixed) + symmetric_cipher_comparison.py + policy_latency.py.
"""

from __future__ import annotations

import os
from typing import List

from evaluation.config import EvalConfig
from evaluation.stats import measure


def run(cfg: EvalConfig) -> List[dict]:
    from pqc_sdn.crypto.symmetric import AeadCipher
    from pqc_sdn.tls.frames import encode_frame, decode_frame, packet_from_frame
    from pqc_sdn.policy.dscp import DscpClass
    from pqc_sdn.policy.engine import PolicyEngine, PolicyMetrics

    print("\n" + "=" * 72)
    print("TABLE 3 — Data Channel / Proxy Overhead")
    print("=" * 72)

    rows = []
    algorithms = ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]

    # ── Per-cipher, per-payload encrypt/decrypt + overhead ────────────────
    for algo in algorithms:
        print(f"\n  Cipher: {algo}")
        for size in cfg.proxy_payloads:
            payload = os.urandom(size)

            # Same key for encrypt + decrypt (raw cipher benchmark, not session)
            key = AeadCipher.generate_key(algo)
            send_cipher = AeadCipher(key, padding_block_size=256, algorithm=algo)
            recv_cipher = AeadCipher(key, padding_block_size=256, algorithm=algo)

            # Encrypt timing
            enc_stats = measure(lambda: send_cipher.encrypt(payload), cfg.n_proxy, unit_scale=1e6)

            # Get wire overhead
            ct = send_cipher.encrypt(payload)
            # Build a minimal SecurePacket-like frame for overhead calc
            from pqc_sdn.tls.session import SecurePacket
            pkt = SecurePacket(
                ciphertext=ct.ciphertext, nonce=ct.nonce,
                sequence_number=0, timestamp=0, key_id="bench", epoch=0
            )
            wire = encode_frame(pkt)
            overhead_bytes = len(wire) - size
            overhead_pct = round(overhead_bytes / size * 100, 2) if size > 0 else 0

            # Decrypt timing (need to prepare packets)
            packets = []
            for i in range(cfg.n_proxy + 20):
                _ct = send_cipher.encrypt(payload)
                packets.append((_ct.nonce, _ct.ciphertext))
            idx = [0]

            def _decrypt():
                n, c = packets[idx[0]]
                recv_cipher.decrypt(n, c)
                idx[0] += 1

            dec_stats = measure(_decrypt, cfg.n_proxy, unit_scale=1e6)

            # Throughput
            enc_mean_us = enc_stats["mean"]
            throughput_mbs = round((size / (1024 * 1024)) / (enc_mean_us / 1e6), 2) if enc_mean_us > 0 else 0

            label = f"{size}B" if size < 1024 else f"{size // 1024}KB"
            print(f"    {label:>6}  enc={enc_stats['mean']:.1f}µs  dec={dec_stats['mean']:.1f}µs  "
                  f"overhead={overhead_bytes}B ({overhead_pct:.0f}%)  {throughput_mbs:.1f} MB/s")

            rows.append({
                "table": 3, "mode": f"cipher_{algo}", "algorithm": algo,
                "operation": "roundtrip",
                "payload_bytes": size, "wire_bytes": len(wire),
                "overhead_bytes": overhead_bytes, "overhead_pct": overhead_pct,
                "throughput_mbs": throughput_mbs,
                "enc_mean_us": enc_stats["mean"], "enc_p99_us": enc_stats["p99"],
                "dec_mean_us": dec_stats["mean"], "dec_p99_us": dec_stats["p99"],
            })

    # ── DSCP policy evaluation latency ────────────────────────────────────
    print(f"\n  DSCP policy evaluation latency ...")
    engine = PolicyEngine()
    for dscp_class in DscpClass:
        stats = measure(
            lambda _d=dscp_class: engine.evaluate(PolicyMetrics(dscp_value=_d.value)),
            cfg.n_policy, unit_scale=1e6
        )
        rec = engine.evaluate(PolicyMetrics(dscp_value=dscp_class.value))
        rows.append({
            "table": 3, "mode": "dscp_policy", "algorithm": rec.algorithm,
            "operation": "policy_eval",
            "dscp_class": dscp_class.name, "dscp_value": dscp_class.value,
            "flow_type": rec.flow_type.value,
            "mean_us": stats["mean"], "p99_us": stats["p99"],
        })

    policy_means = [r["mean_us"] for r in rows if r.get("operation") == "policy_eval"]
    if policy_means:
        import statistics
        print(f"    mean={statistics.mean(policy_means):.2f}µs across all DSCP classes")

    # ── Live tunnel throughput (through real sw_proxy → ctrl_proxy → Ryu) ──
    from evaluation.live_stack_probe import stack_is_up, live_tunnel_throughput

    if stack_is_up():
        print(f"\n  ── Live Tunnel Throughput (sw_proxy:6634 → ctrl_proxy:6652 → Ryu:6653) ──")
        print(f"  Sends OF Echo-Request frames through the real encrypted tunnel.")
        print(f"  Each frame: OVS→sw_proxy(encrypt)→ctrl_proxy(decrypt)→Ryu(echo)→reverse")

        for payload_size in [64, 256, 1024]:
            label = f"{payload_size}B" if payload_size < 1024 else f"{payload_size // 1024}KB"
            n_frames = min(100, cfg.n_proxy)
            result = live_tunnel_throughput(n_frames=n_frames, payload_size=payload_size)

            if result.get("success"):
                print(f"    {label:>6}  {result['frames_sent']} frames → "
                      f"{result['frames_received']} echoed  "
                      f"{result['wall_ms']:.0f}ms  "
                      f"{result['throughput_fps']:.0f} fps  "
                      f"{result['throughput_mbps']:.2f} Mbps")

                rows.append({
                    "table": 3, "mode": "live_tunnel",
                    "algorithm": "live_proxy_pipeline",
                    "operation": "tunnel_throughput",
                    "payload_bytes": payload_size,
                    "frames_sent": result["frames_sent"],
                    "frames_received": result["frames_received"],
                    "throughput_fps": result["throughput_fps"],
                    "throughput_mbs": result["throughput_mbps"],
                    "wall_ms": result["wall_ms"],
                })
            else:
                print(f"    {label:>6}  FAILED: {result.get('error', 'unknown')}")

        # Compare live tunnel vs isolated cipher throughput
        isolated_64 = next((r["throughput_mbs"] for r in rows
                            if r.get("mode") == "cipher_AES-256-GCM"
                            and r.get("payload_bytes") == 64), 0)
        live_64 = next((r["throughput_mbs"] for r in rows
                        if r.get("mode") == "live_tunnel"
                        and r.get("payload_bytes") == 64), 0)
        if isolated_64 > 0 and live_64 > 0:
            ratio = live_64 / isolated_64 * 100
            print(f"\n    Live tunnel vs isolated cipher (64B): "
                  f"{live_64:.1f} vs {isolated_64:.1f} MB/s ({ratio:.0f}%)")
            print(f"    Real-world overhead: TCP + asyncio + buffering + Ryu echo")
    else:
        print(f"\n  ── Live Tunnel Throughput: SKIPPED (stack not running) ──")

    return rows
