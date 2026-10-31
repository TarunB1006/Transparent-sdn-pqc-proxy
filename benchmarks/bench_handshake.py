#!/usr/bin/env python3
"""
Handshake latency benchmark — all 4 algorithm modes.

Measures the full proxy handshake path (ClientHello → ServerRespond →
ClientComplete) used by ControlPlaneService.on_switch_connected and
rehandshake_all, for:
  ML-KEM-512, ML-KEM-768, ML-KEM-1024  (PQC + ML-DSA-87)
  AES-256-GCM                           (classical symmetric baseline)

Also measures individual KEM and DSA micro-ops.

Usage:
    cd pqc-sdn-platform
    python benchmarks/bench_handshake.py            # 200 iterations
    python benchmarks/bench_handshake.py -n 500     # more iterations
    python benchmarks/bench_handshake.py -o out.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqc_sdn.crypto.kem import Kem, KemVariant
from pqc_sdn.crypto.signatures import SignatureScheme
from pqc_sdn.crypto.symmetric import AeadCipher
from pqc_sdn.tls.handshake import HybridHandshake


def _measure(fn, n: int) -> dict:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e3)
    return {
        "mean_ms":   round(statistics.mean(samples), 4),
        "median_ms": round(statistics.median(samples), 4),
        "std_ms":    round(statistics.stdev(samples) if n > 1 else 0, 4),
        "min_ms":    round(min(samples), 4),
        "max_ms":    round(max(samples), 4),
        "p95_ms":    round(sorted(samples)[int(0.95 * n) - 1], 4),
        "p99_ms":    round(sorted(samples)[int(0.99 * n) - 1], 4),
        "n":         n,
    }


def bench_full_handshake(variant: KemVariant, n: int) -> dict:
    def _hs():
        client = HybridHandshake("switch-bench")
        server = HybridHandshake("controller-bench")
        hello = client.create_client_hello(variant)
        sh, cert, encap, _ = server.server_respond(hello)
        client.client_complete(sh, cert, encap)
    return _measure(_hs, n)


def bench_classical_tls(n: int) -> dict:
    """
    Real TLS 1.3 handshake over localhost TCP (X25519 + AES-256-GCM).
    This is the classical baseline — what switch-controller latency would
    look like without PQC, using standard OpenSSL via Python ssl module.
    Requires a self-signed cert; generates one on the fly if not present.
    """
    import ssl, socket, threading, tempfile, subprocess

    # Generate a temporary self-signed cert for the server
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

        samples = []
        errors = 0

        def _server_accept(srv_sock):
            try:
                conn, _ = srv_sock.accept()
                conn.do_handshake()
                conn.close()
            except Exception:
                pass

        for _ in range(n):
            with socket.socket() as raw_srv:
                raw_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                raw_srv.bind(("127.0.0.1", 0))
                port = raw_srv.getsockname()[1]
                raw_srv.listen(1)
                srv_ssl = server_ctx.wrap_socket(raw_srv, server_side=True)

                t = threading.Thread(target=_server_accept, args=(srv_ssl,), daemon=True)
                t.start()

                try:
                    t0 = time.perf_counter()
                    with socket.create_connection(("127.0.0.1", port)) as raw_cli:
                        with client_ctx.wrap_socket(raw_cli) as cli:
                            cli.do_handshake()
                    samples.append((time.perf_counter() - t0) * 1e3)
                except Exception:
                    errors += 1
                t.join(timeout=1)

        if errors:
            print(f"    ({errors} TLS handshake errors ignored)")

    sv = sorted(samples)
    valid_n = len(samples)
    return {
        "mean_ms":   round(statistics.mean(samples), 4),
        "median_ms": round(statistics.median(samples), 4),
        "std_ms":    round(statistics.stdev(samples) if valid_n > 1 else 0, 4),
        "min_ms":    round(min(samples), 4),
        "max_ms":    round(max(samples), 4),
        "p95_ms":    round(sv[int(0.95 * valid_n) - 1], 4),
        "p99_ms":    round(sv[int(0.99 * valid_n) - 1], 4),
        "n":         valid_n,
    }


def bench_kem_ops(variant: KemVariant, n: int) -> dict:
    kem = Kem(variant)
    kp = kem.keygen()
    enc = kem.encapsulate(kp.public_key)
    return {
        "keygen": _measure(kem.keygen, n),
        "encap":  _measure(lambda: kem.encapsulate(kp.public_key), n),
        "decap":  _measure(lambda: kem.decapsulate(kp.secret_key, enc.ciphertext), n),
    }


def bench_dsa_ops(n: int) -> dict:
    dsa = SignatureScheme()
    kp = dsa.keygen()
    msg = b"bench-message"
    sig = dsa.sign(kp.secret_key, msg)
    return {
        "keygen": _measure(dsa.keygen, n),
        "sign":   _measure(lambda: dsa.sign(kp.secret_key, msg), n),
        "verify": _measure(lambda: dsa.verify(kp.public_key, msg, sig), n),
    }


def bench_aes_cipher(n: int) -> dict:
    key = AeadCipher.generate_key()
    cipher = AeadCipher(key, padding_block_size=0)
    payload = os.urandom(1024)
    ct = cipher.encrypt(payload)
    return {
        "enc_1kb": _measure(lambda: cipher.encrypt(payload), n),
        "dec_1kb": _measure(lambda: cipher.decrypt(ct.nonce, ct.ciphertext), n),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--iterations", type=int, default=200)
    ap.add_argument("-o", "--output", default="bench_handshake.csv")
    args = ap.parse_args()
    n = args.iterations

    kem_probe = Kem(KemVariant.ML_KEM_512)
    backend = "liboqs (ML-KEM)" if kem_probe.uses_liboqs else "X25519 fallback"
    print(f"\nBackend : {backend}")
    print(f"Runs    : {n} iterations\n")

    rows = []

    # ── Full handshake ────────────────────────────────────────────────────────
    # Each variant runs in an isolated subprocess so liboqs cache state from
    # one variant cannot warm up the next, giving fair independent measurements.
    print("Full handshake latency:")
    print(f"  {'Algorithm':<16} {'mean':>8} {'p50':>8} {'p95':>8} {'p99':>8} {'std':>8}  (ms)")
    print("  " + "-" * 60)

    import json, subprocess as _sp, tempfile

    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    pythonpath = os.path.join(src_dir, "src")

    _worker = """\
import sys, os, json, statistics, time
sys.path.insert(0, os.environ["PYTHONPATH"])
from pqc_sdn.tls.handshake import HybridHandshake
from pqc_sdn.crypto.kem import KemVariant
variant = KemVariant(sys.argv[1])
n = int(sys.argv[2])
for _ in range(20):
    c=HybridHandshake("c"); s=HybridHandshake("s")
    h=c.create_client_hello(variant); sh,cert,enc,_=s.server_respond(h); c.client_complete(sh,cert,enc)
samples=[]
for _ in range(n):
    c=HybridHandshake("c"); s=HybridHandshake("s")
    t0=time.perf_counter()
    h=c.create_client_hello(variant); sh,cert,enc,_=s.server_respond(h); c.client_complete(sh,cert,enc)
    samples.append((time.perf_counter()-t0)*1000)
sv=sorted(samples)
print(json.dumps({"mean_ms":round(statistics.mean(samples),4),"median_ms":round(statistics.median(samples),4),
    "std_ms":round(statistics.stdev(samples),4),"min_ms":round(min(samples),4),"max_ms":round(max(samples),4),
    "p95_ms":round(sv[int(0.95*n)-1],4),"p99_ms":round(sv[int(0.99*n)-1],4),"n":n}))
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(_worker)
        worker_path = tf.name

    try:
        for variant in KemVariant:
            proc = _sp.run(
                [sys.executable, worker_path, variant.value, str(n)],
                capture_output=True, text=True,
                env={**os.environ, "PYTHONPATH": pythonpath},
            )
            s = json.loads(proc.stdout.strip().splitlines()[-1])
            print(f"  {variant.value:<16} {s['mean_ms']:>8.3f} {s['median_ms']:>8.3f} "
                  f"{s['p95_ms']:>8.3f} {s['p99_ms']:>8.3f} {s['std_ms']:>8.3f}")
            rows.append({"algorithm": variant.value, "operation": "full_handshake", **s})
    finally:
        os.unlink(worker_path)

    s = bench_classical_tls(n)
    print(f"  {'TLS 1.3 (classical)':<16} {s['mean_ms']:>8.3f} {s['median_ms']:>8.3f} "
          f"{s['p95_ms']:>8.3f} {s['p99_ms']:>8.3f} {s['std_ms']:>8.3f}")
    rows.append({"algorithm": "TLS1.3-Classical", "operation": "full_handshake", **s})

    # ── KEM micro-ops ─────────────────────────────────────────────────────────
    print("\nKEM micro-ops (ms):")
    print(f"  {'Variant':<16} {'op':<10} {'mean':>8} {'p99':>8} {'std':>8}")
    print("  " + "-" * 50)
    for variant in KemVariant:
        ops = bench_kem_ops(variant, n)
        for op, s in ops.items():
            print(f"  {variant.value:<16} {op:<10} {s['mean_ms']:>8.4f} {s['p99_ms']:>8.4f} {s['std_ms']:>8.4f}")
            rows.append({"algorithm": variant.value, "operation": f"kem_{op}", **s})

    # ── DSA micro-ops ─────────────────────────────────────────────────────────
    print("\nML-DSA-87 micro-ops (ms):")
    dsa_ops = bench_dsa_ops(n)
    for op, s in dsa_ops.items():
        print(f"  {op:<26} mean={s['mean_ms']:.4f}  p99={s['p99_ms']:.4f}  std={s['std_ms']:.4f}")
        rows.append({"algorithm": "ML-DSA-87", "operation": f"dsa_{op}", **s})

    # ── AES-GCM cipher ops ────────────────────────────────────────────────────
    print("\nAES-256-GCM cipher (1 KB, ms):")
    aes_ops = bench_aes_cipher(n)
    for op, s in aes_ops.items():
        print(f"  {op:<26} mean={s['mean_ms']:.4f}  p99={s['p99_ms']:.4f}  std={s['std_ms']:.4f}")
        rows.append({"algorithm": "AES-256-GCM", "operation": op, **s})

    # ── CSV ───────────────────────────────────────────────────────────────────
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nSaved → {args.output}\n")


if __name__ == "__main__":
    main()
