"""
Table 2 — End-to-End Handshake Protocol Performance.

Three-way: Classical TLS 1.3 vs Our custom PQC handshake (per KEM variant).
Includes: latency, transcript wire size, first encrypted frame overhead,
and concurrent scalability sweep.

Wire size comparison covers all permutations:
  - Classical TLS 1.3:  P-256 ECDHE + ECDSA + AES-256-GCM  (real bytes via proxy)
  - PQC ML-KEM-512  + ML-DSA-87  (our handshake)
  - PQC ML-KEM-768  + ML-DSA-87
  - PQC ML-KEM-1024 + ML-DSA-87
  - First encrypted frame per symmetric cipher: AES-256-GCM / AES-128-GCM / ChaCha20

Methodology: PQC-LEO (subprocess isolation per variant) + our bench_handshake.py logic.
"""

from __future__ import annotations

import json
import os
import select
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from evaluation.config import EvalConfig
from evaluation.stats import measure, describe, iqr_clean


# ═══════════════════════════════════════════════════════════════════
# Handshake latency helpers
# ═══════════════════════════════════════════════════════════════════

def _our_handshake(variant_str: str) -> float:
    """Run one full PQC-SDN handshake, return elapsed ms."""
    from pqc_sdn.tls.handshake import HybridHandshake
    from pqc_sdn.crypto.kem import KemVariant

    variant = KemVariant(variant_str)
    t0 = time.perf_counter()
    sw = HybridHandshake("switch-bench")
    ctrl = HybridHandshake("controller-bench")
    hello = sw.create_client_hello(variant)
    sh, cert, encap, _ = ctrl.server_respond(hello)
    sw.client_complete(sh, cert, encap)
    return (time.perf_counter() - t0) * 1000


def _classical_tls_handshake() -> float:
    """One real TLS 1.3 handshake over localhost, return elapsed ms."""
    with tempfile.TemporaryDirectory() as td:
        key_path = os.path.join(td, "key.pem")
        cert_path = os.path.join(td, "cert.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:P-256",
             "-keyout", key_path, "-out", cert_path,
             "-days", "1", "-nodes", "-subj", "/CN=bench"],
            capture_output=True, check=True,
        )

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert_path, key_path)
        server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        with socket.socket() as raw_srv:
            raw_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_srv.bind(("127.0.0.1", 0))
            port = raw_srv.getsockname()[1]
            raw_srv.listen(1)
            srv_ssl = server_ctx.wrap_socket(raw_srv, server_side=True)

            def _accept():
                try:
                    conn, _ = srv_ssl.accept()
                    conn.do_handshake()
                    conn.close()
                except Exception:
                    pass

            t = threading.Thread(target=_accept, daemon=True)
            t.start()

            t0 = time.perf_counter()
            with socket.create_connection(("127.0.0.1", port)) as raw_cli:
                with client_ctx.wrap_socket(raw_cli) as cli:
                    cli.do_handshake()
            elapsed = (time.perf_counter() - t0) * 1000
            t.join(timeout=1)
            return elapsed


# ═══════════════════════════════════════════════════════════════════
# Wire size measurement — all permutations
# ═══════════════════════════════════════════════════════════════════

def _measure_classical_tls_wire_bytes() -> dict:
    """Measure actual bytes transferred during one TLS 1.3 P-256 handshake.

    Uses a byte-counting TCP proxy between client and server to capture
    the real wire bytes exchanged during do_handshake(). No estimates.
    """
    with tempfile.TemporaryDirectory() as td:
        key_path = os.path.join(td, "key.pem")
        cert_path = os.path.join(td, "cert.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:P-256",
             "-keyout", key_path, "-out", cert_path,
             "-days", "1", "-nodes", "-subj", "/CN=bench"],
            capture_output=True, check=True,
        )

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert_path, key_path)
        server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        bytes_c2s = [0]
        bytes_s2c = [0]

        # Real TLS server on a random port
        real_srv = socket.socket()
        real_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        real_srv.bind(("127.0.0.1", 0))
        real_port = real_srv.getsockname()[1]
        real_srv.listen(1)

        # Byte-counting proxy on a separate port
        proxy_srv = socket.socket()
        proxy_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_srv.bind(("127.0.0.1", 0))
        proxy_port = proxy_srv.getsockname()[1]
        proxy_srv.listen(1)

        def _tls_server():
            try:
                conn, _ = real_srv.accept()
                ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
                ssl_conn.do_handshake()
                ssl_conn.close()
            except Exception:
                pass

        def _proxy():
            try:
                c_conn, _ = proxy_srv.accept()
                s_conn = socket.create_connection(("127.0.0.1", real_port))
                c_conn.setblocking(False)
                s_conn.setblocking(False)

                for _ in range(200):  # safety limit
                    readable, _, _ = select.select([c_conn, s_conn], [], [], 2.0)
                    if not readable:
                        break
                    done = False
                    for sock in readable:
                        try:
                            data = sock.recv(65536)
                        except (BlockingIOError, ConnectionResetError, OSError):
                            continue
                        if not data:
                            done = True
                            break
                        if sock is c_conn:
                            bytes_c2s[0] += len(data)
                            s_conn.sendall(data)
                        else:
                            bytes_s2c[0] += len(data)
                            c_conn.sendall(data)
                    if done:
                        break
                c_conn.close()
                s_conn.close()
            except Exception:
                pass

        t_srv = threading.Thread(target=_tls_server, daemon=True)
        t_proxy = threading.Thread(target=_proxy, daemon=True)
        t_srv.start()
        t_proxy.start()

        try:
            with socket.create_connection(("127.0.0.1", proxy_port)) as raw_cli:
                with client_ctx.wrap_socket(raw_cli) as cli:
                    cli.do_handshake()
        except Exception:
            pass

        # Give threads a moment to finish counting
        time.sleep(0.2)
        t_srv.join(timeout=2)
        t_proxy.join(timeout=2)
        proxy_srv.close()
        real_srv.close()

    return {
        "client_to_server_bytes": bytes_c2s[0],
        "server_to_client_bytes": bytes_s2c[0],
        "transcript_total_bytes": bytes_c2s[0] + bytes_s2c[0],
    }


def _measure_pqc_transcript_size(variant_str: str) -> dict:
    """Measure byte sizes of each PQC handshake message for one KEM variant.

    Our handshake protocol:
      Client → Server: ClientHello (KEM public key + identity)
      Server → Client: ServerHello, Certificate (ML-DSA-87 pubkey + sig), EncapsulatedKey
    Each message is length-prefixed on wire (4-byte uint32 header).
    """
    from pqc_sdn.tls.handshake import HybridHandshake
    from pqc_sdn.crypto.kem import KemVariant

    variant = KemVariant(variant_str)
    sw = HybridHandshake("switch-bench")
    ctrl = HybridHandshake("controller-bench")

    hello = sw.create_client_hello(variant)
    ch_bytes = len(hello.serialize())

    sh, cert, encap, _ = ctrl.server_respond(hello)
    sh_bytes = len(sh.serialize())
    cert_bytes = len(cert.serialize())
    encap_bytes = len(encap.serialize())

    sw.client_complete(sh, cert, encap)

    payload_total = ch_bytes + sh_bytes + cert_bytes + encap_bytes
    wire_headers = 4 * 4  # 4 messages × 4-byte length prefix
    preamble = 8  # PQC\x02 (4 bytes) + conn_id (4 bytes)

    return {
        "client_hello_bytes": ch_bytes,
        "server_hello_bytes": sh_bytes,
        "certificate_bytes": cert_bytes,
        "encapsulated_key_bytes": encap_bytes,
        "transcript_payload_bytes": payload_total,
        "transcript_total_bytes": payload_total + wire_headers + preamble,
    }


def _measure_first_frame_overhead() -> list[dict]:
    """Measure the first encrypted data frame size per symmetric cipher.

    After the handshake, the first OpenFlow message is encrypted with the
    DSCP-selected symmetric cipher. Different ciphers produce different
    ciphertext expansion (nonce size, auth tag size, padding).

    Uses a standard 72-byte OpenFlow PacketIn as the reference payload.
    """
    from pqc_sdn.crypto.symmetric import AeadCipher
    from pqc_sdn.tls.session import SecureSession, SecurePacket
    from pqc_sdn.tls.frames import encode_frame

    of_frame = b"\x04\x0a\x00\x48" + b"\x00" * 68  # 72-byte PacketIn
    results = []

    for cipher_name in ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]:
        key = AeadCipher.generate_key(cipher_name)
        cipher = AeadCipher(key, padding_block_size=256, algorithm=cipher_name)
        ct = cipher.encrypt(of_frame)

        pkt = SecurePacket(
            ciphertext=ct.ciphertext, nonce=ct.nonce,
            sequence_number=0, timestamp=0, key_id="bench", epoch=0,
        )
        wire = encode_frame(pkt)

        results.append({
            "cipher": cipher_name,
            "plaintext_bytes": len(of_frame),
            "ciphertext_bytes": len(ct.ciphertext),
            "nonce_bytes": len(ct.nonce),
            "wire_frame_bytes": len(wire),
            "frame_overhead_bytes": len(wire) - len(of_frame),
            "frame_overhead_pct": round((len(wire) - len(of_frame)) / len(of_frame) * 100, 1),
        })

    return results


# ═══════════════════════════════════════════════════════════════════
# Scalability
# ═══════════════════════════════════════════════════════════════════

def _scalability_sweep(variant_str: str, concurrency: int, total: int) -> dict:
    """Run `total` handshakes at given concurrency, return stats."""
    samples = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(_our_handshake, variant_str) for _ in range(total)]
        wall_start = time.perf_counter()
        for f in as_completed(futs):
            try:
                samples.append(f.result())
            except Exception:
                pass
        wall_elapsed = time.perf_counter() - wall_start

    if not samples:
        return {}
    stats = describe(iqr_clean(samples))
    stats["concurrency"] = concurrency
    stats["wall_sec"] = round(wall_elapsed, 3)
    stats["throughput_hps"] = round(len(samples) / wall_elapsed, 1)
    return stats


# ═══════════════════════════════════════════════════════════════════
# Main runner
# ═══════════════════════════════════════════════════════════════════

def run(cfg: EvalConfig) -> List[dict]:
    from pqc_sdn.crypto.kem import KemVariant

    print("\n" + "=" * 72)
    print("TABLE 2 — Handshake Protocol Performance")
    print("=" * 72)

    rows = []

    # ══════════════════════════════════════════════════════════════
    # Part 1: Handshake Latency (3-way comparison)
    # ══════════════════════════════════════════════════════════════

    # ── Mode A: Classical TLS 1.3 ─────────────────────────────────
    print("\n  [A] Classical TLS 1.3 (P-256 + ECDSA + AES-256-GCM) ...")
    tls_samples = []
    for _ in range(cfg.n_classical_tls):
        try:
            tls_samples.append(_classical_tls_handshake())
        except Exception:
            pass
    if tls_samples:
        stats = describe(iqr_clean(tls_samples))
        rows.append({"table": 2, "mode": "A_classical_tls13", "algorithm": "TLS1.3-P256",
                      "concurrency": 1, **stats})
        print(f"    mean={stats['mean']:.3f}ms  p95={stats['p95']:.3f}ms")

    # ── Mode C: Our PQC handshake per KEM variant ─────────────────
    for variant in KemVariant:
        print(f"  [C] PQC-SDN handshake — {variant.value} + ML-DSA-87 ...")
        samples = [_our_handshake(variant.value) for _ in range(cfg.n_handshake)]
        stats = describe(iqr_clean(samples))

        # Transcript size (deterministic per variant)
        transcript = _measure_pqc_transcript_size(variant.value)
        stats.update(transcript)

        rows.append({"table": 2, "mode": "C_pqc_sdn", "algorithm": variant.value,
                      "concurrency": 1, **stats})
        print(f"    mean={stats['mean']:.3f}ms  p95={stats['p95']:.3f}ms  cov={stats['cov_pct']:.1f}%")

    # ── Latency overhead vs classical ─────────────────────────────
    tls_mean = rows[0]["mean"] if rows else 0
    for r in rows[1:]:
        if r.get("mode") == "C_pqc_sdn":
            overhead = ((r["mean"] - tls_mean) / tls_mean * 100) if tls_mean > 0 else 0
            r["overhead_vs_classical_pct"] = round(overhead, 1)
            print(f"    {r['algorithm']}: latency overhead {overhead:+.1f}% vs classical")

    # ══════════════════════════════════════════════════════════════
    # Part 2: Wire Size Comparison (all permutations)
    # ══════════════════════════════════════════════════════════════

    print(f"\n  ── Wire Size: Handshake Transcript ──")

    # Classical TLS wire bytes (real measurement via byte-counting proxy)
    print(f"  Measuring classical TLS 1.3 wire bytes ...")
    try:
        tls_wire = _measure_classical_tls_wire_bytes()
        tls_total = tls_wire["transcript_total_bytes"]
        rows.append({"table": 2, "mode": "wire_size", "algorithm": "TLS1.3-P256",
                      "kem": "P-256 ECDHE", "signature": "ECDSA-P256",
                      **tls_wire})
        print(f"    TLS 1.3 P-256: {tls_total:,}B  "
              f"(c→s={tls_wire['client_to_server_bytes']:,}B  "
              f"s→c={tls_wire['server_to_client_bytes']:,}B)")
    except Exception as e:
        print(f"    ⚠ Classical TLS measurement failed: {e}")
        tls_total = 0

    # PQC handshake wire sizes per KEM variant
    for variant in KemVariant:
        transcript = _measure_pqc_transcript_size(variant.value)
        pqc_total = transcript["transcript_total_bytes"]
        expansion = round(pqc_total / tls_total, 1) if tls_total > 0 else 0

        rows.append({
            "table": 2, "mode": "wire_size", "algorithm": variant.value,
            "kem": variant.value, "signature": "ML-DSA-87",
            "expansion_vs_classical": expansion,
            **transcript,
        })
        print(f"    {variant.value} + ML-DSA-87: {pqc_total:,}B  "
              f"(CH={transcript['client_hello_bytes']:,} "
              f"SH={transcript['server_hello_bytes']:,} "
              f"Cert={transcript['certificate_bytes']:,} "
              f"Encap={transcript['encapsulated_key_bytes']:,})  "
              f"→ {expansion}x classical")

    # First encrypted frame per symmetric cipher
    print(f"\n  ── Wire Size: First Encrypted Frame (72B OpenFlow PacketIn) ──")
    frame_rows = _measure_first_frame_overhead()
    for fr in frame_rows:
        rows.append({"table": 2, "mode": "first_frame", **fr})
        print(f"    {fr['cipher']:<22} plain={fr['plaintext_bytes']}B → "
              f"wire={fr['wire_frame_bytes']}B  "
              f"overhead={fr['frame_overhead_bytes']}B ({fr['frame_overhead_pct']}%)")

    # ══════════════════════════════════════════════════════════════
    # Part 3: Summary table
    # ══════════════════════════════════════════════════════════════

    print(f"\n  ── Complete Wire Size Comparison ──")
    print(f"    {'Algorithm':<28} {'KEM':<14} {'Sig':<12} {'Handshake':>10} {'1st Frame':>10} {'Total':>10} {'vs TLS':>8}")
    print(f"    {'-' * 90}")

    # For each KEM × cipher combination, show total setup cost
    wire_rows = [r for r in rows if r.get("mode") == "wire_size"]
    for wr in wire_rows:
        kem = wr.get("kem", "—")
        sig = wr.get("signature", "—")
        hs_bytes = wr.get("transcript_total_bytes", 0)

        if wr["algorithm"] == "TLS1.3-P256":
            # Classical has no separate "first frame" — TLS handles it
            print(f"    {wr['algorithm']:<28} {kem:<14} {sig:<12} "
                  f"{hs_bytes:>9,}B {'—':>10} {hs_bytes:>9,}B {'1.0x':>8}")
        else:
            for fr in frame_rows:
                combo = f"{wr['algorithm']} + {fr['cipher']}"
                frame_bytes = fr["wire_frame_bytes"]
                total = hs_bytes + frame_bytes
                expansion = round(total / tls_total, 1) if tls_total > 0 else 0
                print(f"    {combo:<28} {kem:<14} {sig:<12} "
                      f"{hs_bytes:>9,}B {frame_bytes:>9,}B "
                      f"{total:>9,}B {expansion:>7.1f}x")

    # ══════════════════════════════════════════════════════════════
    # Part 4: Live Stack Handshake (through real sw_proxy → ctrl_proxy)
    # ══════════════════════════════════════════════════════════════

    from evaluation.live_stack_probe import stack_is_up, live_handshake_as_switch

    if stack_is_up():
        print(f"\n  ── Live Stack Handshake (sw_proxy:6634 → ctrl_proxy:6652 → Ryu:6653) ──")
        print(f"  This measures the REAL end-to-end handshake including TCP, asyncio,")
        print(f"  threadpool executor, ML-KEM over wire, and Ryu registration.")

        live_samples = []
        n_live = min(cfg.n_handshake, 10)  # fewer iterations — each is a real TCP connection
        for i in range(n_live):
            result = live_handshake_as_switch(timeout=15.0)
            if result.get("success"):
                live_samples.append(result["handshake_ms"])
                if i == 0:
                    print(f"    First connection: {result['handshake_ms']:.1f}ms "
                          f"(OF version=0x{result.get('of_version', 0):02x} "
                          f"type={result.get('first_msg_type', '?')})")
            else:
                print(f"    Connection {i+1} failed: {result.get('error', 'unknown')}")

        if live_samples:
            live_stats = describe(iqr_clean(live_samples))
            rows.append({
                "table": 2, "mode": "D_live_stack", "algorithm": "live_proxy_handshake",
                "concurrency": 1, **live_stats,
            })
            # Compare with in-process handshake
            inproc_mean = next((r["mean"] for r in rows if r.get("mode") == "C_pqc_sdn"
                                and r.get("algorithm") == "ML-KEM-512"), 0)
            live_overhead = ((live_stats["mean"] - inproc_mean) / inproc_mean * 100
                             if inproc_mean > 0 else 0)
            print(f"    Live stack:  mean={live_stats['mean']:.1f}ms  p95={live_stats['p95']:.1f}ms")
            print(f"    In-process:  mean={inproc_mean:.1f}ms")
            print(f"    Real-world overhead: +{live_overhead:.0f}% "
                  f"(TCP + asyncio + threadpool + Ryu registration)")
        else:
            print(f"    ⚠ All live handshake attempts failed")
    else:
        print(f"\n  ── Live Stack Handshake: SKIPPED (stack not running) ──")
        print(f"    Start the stack to measure real handshake latency")

    # ══════════════════════════════════════════════════════════════
    # Part 5: Scalability sweep
    # ══════════════════════════════════════════════════════════════

    print(f"\n  ── Scalability sweep (ML-KEM-512, concurrency={cfg.concurrency_levels}) ──")
    for c in cfg.concurrency_levels:
        stats = _scalability_sweep("ML-KEM-512", c, cfg.n_scalability)
        if stats:
            stats["table"] = 2
            stats["mode"] = "C_pqc_sdn_scalability"
            stats["algorithm"] = "ML-KEM-512"
            rows.append(stats)
            print(f"    c={c:>3}  mean={stats['mean']:.3f}ms  throughput={stats['throughput_hps']:.0f} hs/s")

    return rows
