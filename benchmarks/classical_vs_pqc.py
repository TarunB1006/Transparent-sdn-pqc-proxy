#!/usr/bin/env python3
"""
Classical vs PQC handshake & micro-op comparison benchmark.
Patches _LIBOQS=False at runtime to force X25519+Ed25519 classical path,
then runs the same benchmark with real liboqs PQC.
"""

import csv
import os
import statistics
import time
from typing import List

import importlib
import sys

# Pre-import oqs so we can restore it later
import oqs as _oqs_module

def _reload_crypto(use_liboqs: bool):
    """Reload crypto modules with liboqs enabled or disabled."""
    if not use_liboqs:
        sys.modules["oqs"] = None          # make 'import oqs' raise ImportError
    else:
        sys.modules["oqs"] = _oqs_module   # restore real module

    for mod_name in [
        "pqc_sdn.crypto.kem",
        "pqc_sdn.crypto.signatures",
        "pqc_sdn.tls.handshake",
    ]:
        if mod_name in sys.modules:
            importlib.reload(sys.modules[mod_name])

# Initial load with PQC (default)
_reload_crypto(True)
from pqc_sdn.crypto.kem import Kem, KemVariant
from pqc_sdn.crypto.signatures import SignatureScheme
from pqc_sdn.tls.handshake import HybridHandshake

N = 1000


def _measure(fn, n=N) -> dict:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e3)
    return {
        "mean": round(statistics.mean(samples), 4),
        "std":  round(statistics.stdev(samples), 4),
        "min":  round(min(samples), 4),
        "max":  round(max(samples), 4),
    }


def run_suite(label: str, use_liboqs: bool) -> List[dict]:
    _reload_crypto(use_liboqs)
    # Re-import fresh symbols after reload
    from pqc_sdn.crypto.kem import Kem, KemVariant
    from pqc_sdn.crypto.signatures import SignatureScheme
    from pqc_sdn.tls.handshake import HybridHandshake
    rows = []

    def _add(op, variant_label, stats):
        rows.append({"backend": label, "algorithm": variant_label,
                     "operation": op, **stats})

    # ── KEM micro-ops for each variant ───────────────────────────────────────
    for variant in KemVariant:
        kem = Kem(variant)
        kp  = kem.keygen()
        enc = kem.encapsulate(kp.public_key)
        _add("kem_keygen", variant.value, _measure(kem.keygen))
        _add("kem_encap",  variant.value, _measure(lambda: kem.encapsulate(kp.public_key)))
        _add("kem_decap",  variant.value, _measure(lambda: kem.decapsulate(kp.secret_key, enc.ciphertext)))

    # ── DSA micro-ops (algorithm-agnostic, one entry) ────────────────────────
    dsa = SignatureScheme()
    kp  = dsa.keygen()
    msg = b"benchmark"
    sig = dsa.sign(kp.secret_key, msg)
    _add("dsa_keygen", "DSA", _measure(dsa.keygen))
    _add("dsa_sign",   "DSA", _measure(lambda: dsa.sign(kp.secret_key, msg)))
    _add("dsa_verify", "DSA", _measure(lambda: dsa.verify(kp.public_key, msg, sig)))

    # ── Full handshake per variant ────────────────────────────────────────────
    for variant in KemVariant:
        def _hs(v=variant):
            c = HybridHandshake("client")
            s = HybridHandshake("server")
            hello = c.create_client_hello(v)
            sh, cert, encap, _ = s.server_respond(hello)
            c.client_complete(sh, cert, encap)
        _add("full_handshake", variant.value, _measure(_hs))

    return rows


# ── Classical run ─────────────────────────────────────────────────────────────
print("Running classical (X25519 + Ed25519) ...")
classical_rows = run_suite("Classical (X25519+Ed25519)", use_liboqs=False)

# ── PQC run ───────────────────────────────────────────────────────────────────
print("Running PQC (liboqs ML-KEM + ML-DSA-87) ...")
pqc_rows = run_suite("PQC (ML-KEM + ML-DSA-87)", use_liboqs=True)

all_rows = classical_rows + pqc_rows

# ── Print comparison table ────────────────────────────────────────────────────
OPS = ["full_handshake", "kem_keygen", "kem_encap", "kem_decap",
       "dsa_keygen", "dsa_sign", "dsa_verify"]
OP_LABEL = {
    "full_handshake": "Full Handshake",
    "kem_keygen": "KEM KeyGen", "kem_encap": "KEM Encap", "kem_decap": "KEM Decap",
    "dsa_keygen": "DSA KeyGen", "dsa_sign":  "DSA Sign",  "dsa_verify": "DSA Verify",
}

# Build lookup: (backend, algorithm, operation) -> stats
lookup = {(r["backend"], r["algorithm"], r["operation"]): r for r in all_rows}

VARIANTS = [v.value for v in KemVariant]
CL = "Classical (X25519+Ed25519)"
PQ = "PQC (ML-KEM + ML-DSA-87)"

print("\n" + "="*105)
print("Classical vs PQC Comparison  (latency in ms, n=1000)")
print("="*105)
print(f"{'Operation':<18} {'Variant':<14} {'Classical mean±std':>20}  {'PQC mean±std':>20}  {'Overhead':>10}")
print("-"*105)

for op in OPS:
    alg_keys = VARIANTS if op != "dsa_keygen" and "dsa" in op or op in ("dsa_keygen","dsa_sign","dsa_verify") else VARIANTS
    if "dsa" in op:
        cl = lookup.get((CL, "DSA", op))
        pq = lookup.get((PQ, "DSA", op))
        if cl and pq:
            overhead = ((pq["mean"] - cl["mean"]) / cl["mean"] * 100)
            print(f"{OP_LABEL[op]:<18} {'ML-DSA-87':<14} "
                  f"{cl['mean']:>8.4f}±{cl['std']:<8.4f}  "
                  f"{pq['mean']:>8.4f}±{pq['std']:<8.4f}  "
                  f"{overhead:>+9.1f}%")
    else:
        for variant in VARIANTS:
            cl = lookup.get((CL, variant, op))
            pq = lookup.get((PQ, variant, op))
            if cl and pq:
                overhead = ((pq["mean"] - cl["mean"]) / cl["mean"] * 100)
                print(f"{OP_LABEL[op]:<18} {variant:<14} "
                      f"{cl['mean']:>8.4f}±{cl['std']:<8.4f}  "
                      f"{pq['mean']:>8.4f}±{pq['std']:<8.4f}  "
                      f"{overhead:>+9.1f}%")
    if op in ("kem_decap", "dsa_verify"):
        print()

print("="*105)
print(f"n = {N} iterations per operation\n")

# ── CSV ───────────────────────────────────────────────────────────────────────
with open("classical_vs_pqc.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
    writer.writeheader()
    writer.writerows(all_rows)
print("Saved → classical_vs_pqc.csv")
