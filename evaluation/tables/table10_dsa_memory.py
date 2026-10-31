"""Table 10 — DSA Algorithm Comparison + Memory Under Load."""

from __future__ import annotations
import gc, os, statistics, time, tracemalloc
from typing import List
from evaluation.config import EvalConfig, WARMUP_ITERATIONS
from evaluation.stats import describe, iqr_clean

def run(cfg: EvalConfig) -> List[dict]:
    print("\n" + "=" * 72)
    print("TABLE 10 — DSA Algorithm Comparison & Memory Under Load")
    print("=" * 72)
    rows = []
    n = cfg.n_primitive
    msg = os.urandom(64)

    # 10A: DSA comparison
    print("\n  [10A] DSA Algorithm Comparison")
    print(f"    {'Algorithm':<14} {'PK':>5} {'Sig':>5} {'Keygen':>8} {'Sign':>8} {'Verify':>8} {'QS':>6}")

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    for _ in range(WARMUP_ITERATIONS): Ed25519PrivateKey.generate()
    kg=[]; si=[]; ve=[]
    for _ in range(n):
        t0=time.perf_counter(); k=Ed25519PrivateKey.generate(); kg.append((time.perf_counter()-t0)*1e6)
        t0=time.perf_counter(); s=k.sign(msg); si.append((time.perf_counter()-t0)*1e6)
        t0=time.perf_counter(); k.public_key().verify(s,msg); ve.append((time.perf_counter()-t0)*1e6)
    mk,ms,mv=statistics.mean(iqr_clean(kg)),statistics.mean(iqr_clean(si)),statistics.mean(iqr_clean(ve))
    print(f"    {'Ed25519':<14} {32:>5} {64:>5} {mk:>8.1f} {ms:>8.1f} {mv:>8.1f} {'128':>6}")
    rows.append({"table":10,"section":"10A_dsa","algorithm":"Ed25519","pk_bytes":32,"sig_bytes":64,
                 "keygen_us":round(mk,2),"sign_us":round(ms,2),"verify_us":round(mv,2),
                 "security_bits":128,"quantum_safe":False})

    try:
        import oqs
        for alg,sec in [("ML-DSA-44",128),("ML-DSA-65",192),("ML-DSA-87",256)]:
            for _ in range(WARMUP_ITERATIONS):
                with oqs.Signature(alg) as s:
                    pk=s.generate_keypair(); sg=s.sign(msg); s.verify(msg,sg,pk)
            kg=[]; si=[]; ve=[]; pk_sz=sig_sz=0
            for _ in range(n):
                with oqs.Signature(alg) as s:
                    t0=time.perf_counter(); pk=s.generate_keypair(); kg.append((time.perf_counter()-t0)*1e6)
                    t0=time.perf_counter(); sg=s.sign(msg); si.append((time.perf_counter()-t0)*1e6)
                    t0=time.perf_counter(); s.verify(msg,sg,pk); ve.append((time.perf_counter()-t0)*1e6)
                    pk_sz=len(pk); sig_sz=len(sg)
            mk,ms,mv=statistics.mean(iqr_clean(kg)),statistics.mean(iqr_clean(si)),statistics.mean(iqr_clean(ve))
            ed_s=next((r["sign_us"] for r in rows if r.get("algorithm")=="Ed25519"),1)
            ovh=round((ms/ed_s-1)*100,0)
            print(f"    {alg:<14} {pk_sz:>5} {sig_sz:>5} {mk:>8.1f} {ms:>8.1f} {mv:>8.1f} {str(sec):>6}  sign {ovh:+.0f}% vs Ed25519")
            rows.append({"table":10,"section":"10A_dsa","algorithm":alg,"pk_bytes":pk_sz,"sig_bytes":sig_sz,
                         "keygen_us":round(mk,2),"sign_us":round(ms,2),"verify_us":round(mv,2),
                         "security_bits":sec,"quantum_safe":True,"sign_overhead_vs_ed25519_pct":ovh})
    except ImportError:
        print("    liboqs not available")

    # 10B: Memory
    print("\n  [10B] Memory Under Concurrent Sessions")
    from pqc_sdn.tls.session import SecureSession, derive_directional_keys
    for ns in [1,5,10,20,50,100,200]:
        gc.collect(); tracemalloc.start()
        sessions=[]
        for i in range(ns):
            sk,rk=derive_directional_keys(os.urandom(32),f"s{i}")
            sessions.append(SecureSession(f"s{i}",sk,rk,f"k{i}","sw","ctrl"))
        _,peak=tracemalloc.get_traced_memory(); tracemalloc.stop()
        per=peak/1024/ns if ns>0 else 0
        del sessions; gc.collect()
        note="k=4 fat-tree" if ns==20 else ""
        print(f"    {ns:>5} sessions: {peak/1024:>7.1f}KB  {per:>5.2f}KB/sess  {note}")
        rows.append({"table":10,"section":"10B_memory","n_sessions":ns,
                     "peak_memory_kb":round(peak/1024,2),"per_session_kb":round(per,2),"note":note})
    return rows
