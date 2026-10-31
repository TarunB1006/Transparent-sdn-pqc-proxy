#!/usr/bin/env python3
"""
attack_impact.py — Measure the performance impact of attack-detection overhead.

Quantifies how much the security mechanisms (replay-window lookup, MAC
verification, sequence-number tracking) add to per-frame latency compared
to a raw AeadCipher with no session state.

Scenarios:
  A. Raw encrypt/decrypt (no session) — baseline
  B. SecureSession encrypt/decrypt — with seq-no, replay window, MAC
  C. SecureSession under replay storm — 20% of frames are duplicates

Run:
    PYTHONPATH=src python3 benchmarks/attack_impact.py
"""

import csv
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqc_sdn.crypto.symmetric import AeadCipher
from pqc_sdn.tls.session import SecureSession, SessionError
from pqc_sdn.tls.frames import encode_frame, decode_frame, packet_from_frame
from pqc_sdn.tls.handshake import HybridHandshake
from pqc_sdn.crypto.kem import KemVariant
from pqc_sdn.channel.orchestrator import ProxyOrchestrator
from pqc_sdn.channel.registry import SessionRegistry


N = 5000
OF_FRAME = b"\x04\x0a\x00\x48" + b"\x00" * 68   # 72-byte PacketIn


def make_session():
    ctrl = HybridHandshake("controller")
    sw   = HybridHandshake("switch-bench")
    hello = sw.create_client_hello(KemVariant.ML_KEM_512)
    s_hello, cert, encap, _ = ctrl.server_respond(hello)
    result = sw.client_complete(s_hello, cert, encap)
    orch = ProxyOrchestrator(SessionRegistry())
    orch.activate_control_plane(42, result.session)
    plans = orch.plans_for_switch(42)
    p = plans[0]
    sk = bytes.fromhex(p["send_key_hex"])
    rk = bytes.fromhex(p["recv_key_hex"])
    kid, ctx = p["key_id"], p["ctx"]
    # send encrypts with sk (its send_key); recv decrypts with sk (its recv_key).
    # Keys are swapped: recv's send_key=rk, recv_key=sk so .decrypt() uses sk.
    send = SecureSession(ctx, sk, rk, kid, "sender", "receiver")
    recv = SecureSession(ctx, rk, sk, kid, "receiver", "sender")
    return send, recv


print("PQC Attack-Detection Overhead Benchmark")
print("=" * 60)

rows = []

# ── A. Raw cipher (no session state) ──────────────────────────────────────────
key = AeadCipher.generate_key("AES-256-GCM")
raw = AeadCipher(key, padding_block_size=0, algorithm="AES-256-GCM")

enc_raw, dec_raw = [], []
for _ in range(N):
    t0 = time.perf_counter()
    ct = raw.encrypt(OF_FRAME)
    enc_raw.append((time.perf_counter() - t0) * 1e6)

ct_raw = raw.encrypt(OF_FRAME)
for _ in range(N):
    t0 = time.perf_counter()
    raw.decrypt(ct_raw.nonce, ct_raw.ciphertext)
    dec_raw.append((time.perf_counter() - t0) * 1e6)

enc_raw_mean = statistics.mean(enc_raw)
dec_raw_mean = statistics.mean(dec_raw)
rows.append({"scenario": "A_raw_cipher", "enc_mean_us": round(enc_raw_mean, 3),
             "dec_mean_us": round(dec_raw_mean, 3), "replay_detected": 0,
             "overhead_vs_raw_pct": 0.0})
print(f"\nA. Raw AeadCipher (no session):  enc={enc_raw_mean:.3f}µs  dec={dec_raw_mean:.3f}µs")

# ── B. SecureSession normal path ───────────────────────────────────────────────
send, recv = make_session()

enc_sess, dec_sess = [], []
frames = []
for _ in range(N):
    t0 = time.perf_counter()
    pkt = send.encrypt(OF_FRAME)
    enc_sess.append((time.perf_counter() - t0) * 1e6)
    frames.append(encode_frame(pkt))

for wire in frames:
    t0 = time.perf_counter()
    wf = decode_frame(wire)
    pkt = packet_from_frame(wf, recv.key_id)
    recv.decrypt(pkt)
    dec_sess.append((time.perf_counter() - t0) * 1e6)

enc_sess_mean = statistics.mean(enc_sess)
dec_sess_mean = statistics.mean(dec_sess)
enc_overhead = 100.0 * (enc_sess_mean - enc_raw_mean) / enc_raw_mean
dec_overhead = 100.0 * (dec_sess_mean - dec_raw_mean) / dec_raw_mean
rows.append({"scenario": "B_secure_session", "enc_mean_us": round(enc_sess_mean, 3),
             "dec_mean_us": round(dec_sess_mean, 3), "replay_detected": 0,
             "overhead_vs_raw_pct": round((enc_overhead + dec_overhead) / 2, 1)})
print(f"B. SecureSession (normal):       enc={enc_sess_mean:.3f}µs (+{enc_overhead:.1f}%)  "
      f"dec={dec_sess_mean:.3f}µs (+{dec_overhead:.1f}%)")

# ── C. Replay storm — 20% of frames are duplicates ────────────────────────────
send2, recv2 = make_session()

REPLAY_RATE = 0.20
detected = 0
dec_storm = []
storm_frames = [encode_frame(send2.encrypt(OF_FRAME)) for _ in range(N)]

for i, wire in enumerate(storm_frames):
    replay = (i % 5 == 4)  # every 5th frame is a replay of the previous
    target = storm_frames[i - 1] if replay and i > 0 else wire
    t0 = time.perf_counter()
    try:
        wf = decode_frame(target)
        pkt = packet_from_frame(wf, recv2.key_id)
        recv2.decrypt(pkt)
    except SessionError:
        detected += 1
    dec_storm.append((time.perf_counter() - t0) * 1e6)

dec_storm_mean = statistics.mean(dec_storm)
storm_overhead = 100.0 * (dec_storm_mean - dec_raw_mean) / dec_raw_mean
rows.append({"scenario": f"C_replay_storm_{int(REPLAY_RATE*100)}pct",
             "enc_mean_us": round(enc_sess_mean, 3),
             "dec_mean_us": round(dec_storm_mean, 3),
             "replay_detected": detected,
             "overhead_vs_raw_pct": round(storm_overhead, 1)})
print(f"C. SecureSession (20% replays):  dec={dec_storm_mean:.3f}µs (+{storm_overhead:.1f}%)"
      f"  replays detected={detected}/{int(N*REPLAY_RATE)}")

print("\n── Summary")
print(f"  Session state overhead (enc): +{enc_overhead:.1f}%  (seq-no + MAC)")
print(f"  Session state overhead (dec): +{dec_overhead:.1f}%  (replay window lookup + MAC verify)")
print(f"  Replay storm (20%) extra dec: +{storm_overhead - dec_overhead:.1f}%  (window scan)")
print(f"  Replay detection rate: {detected}/{int(N*REPLAY_RATE)}  ({100*detected/max(int(N*REPLAY_RATE),1):.0f}%)")
print("\n  Security overhead is small (~µs per frame) — control-plane traffic is")
print("  latency-tolerant at this scale. Data-plane is unaffected (not encrypted by proxy).")

out = os.path.join(os.path.dirname(__file__), "..", "results", "attack_impact.csv")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
print(f"\nSaved → {os.path.relpath(out)}")
