"""
bench_cp_saturation.py — Find the proxy's control-plane message throughput ceiling.

Floods the sw_proxy with synthetic OpenFlow messages at increasing rates
and measures how many msgs/sec get through before the proxy saturates.

This answers: "At what point does PQC encryption become the bottleneck?"
— which is the RIGHT throughput metric (not link-capped iperf).

Usage:
    PYTHONPATH=src PQC_CP_METRICS=1 python3 evaluation/bench_cp_saturation.py
"""

from __future__ import annotations
import asyncio
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


async def flood_proxy(host: str, port: int, n_msgs: int, msg_size: int = 64) -> dict:
    """Connect to sw_proxy, do PQC handshake, then flood with OF messages."""
    from pqc_sdn.tls.handshake import HybridHandshake, derive_directional_keys
    from pqc_sdn.tls.session import MultiCipherSession
    from pqc_sdn.tls.frames import encode_frame, CIPHER_AES_256_GCM

    reader, writer = await asyncio.open_connection(host, port)

    # PQC handshake preamble
    conn_id = int.from_bytes(os.urandom(4), "big")
    writer.write(b"PQC\x02" + struct.pack("!I", conn_id))
    await writer.drain()

    # Handshake
    hs = HybridHandshake(f"flood-{conn_id}")
    ch = hs.create_client_hello()
    ch_raw = ch.serialize()
    writer.write(struct.pack("!I", len(ch_raw)) + ch_raw)
    await writer.drain()

    # Read server response (3 messages)
    from pqc_sdn.tls.messages import ServerHello, Certificate, EncapsulatedKey
    msgs = []
    buf = b""
    while len(msgs) < 3:
        chunk = await reader.read(65536)
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 4:
            mlen = struct.unpack_from("!I", buf, 0)[0]
            if len(buf) < 4 + mlen:
                break
            msgs.append(buf[4:4+mlen])
            buf = buf[4+mlen:]

    if len(msgs) < 3:
        writer.close()
        return {"error": "handshake incomplete"}

    sh = ServerHello.deserialize(msgs[0])
    cert = Certificate.deserialize(msgs[1])
    encap = EncapsulatedKey.deserialize(msgs[2])
    secret = hs.client_complete(sh, cert, encap)
    send_key, recv_key = derive_directional_keys(secret, sh.session_id)

    session = MultiCipherSession(
        sh.session_id, send_key, recv_key,
        f"key-flood", "flood", "proxy"
    )

    # Build a fake OF Hello message of desired size
    of_hello = struct.pack("!BBHI", 0x04, 0, max(8, msg_size), 1) + b"\x00" * max(0, msg_size - 8)

    # Flood
    t0 = time.perf_counter()
    bytes_sent = 0
    for i in range(n_msgs):
        pkt = session.encrypt(of_hello, cipher_name="AES-256-GCM")
        frame = encode_frame(pkt, cipher_id=CIPHER_AES_256_GCM)
        writer.write(frame)
        bytes_sent += len(frame)
        if i % 100 == 0:
            await writer.drain()

    await writer.drain()
    elapsed = time.perf_counter() - t0

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    return {
        "n_msgs": n_msgs,
        "msg_size": msg_size,
        "elapsed_s": round(elapsed, 4),
        "msgs_per_sec": round(n_msgs / elapsed, 1),
        "mbps": round(bytes_sent * 8 / elapsed / 1e6, 2),
        "bytes_sent": bytes_sent,
    }


async def run_saturation_test():
    """Run increasing message counts to find the saturation point."""
    print("═" * 60)
    print("  CP Throughput Saturation Test")
    print("═" * 60)
    print()

    host = "127.0.0.1"
    port = 6634

    # Test at different message sizes (typical OF messages)
    msg_sizes = [8, 64, 128, 512, 1024]
    n_msgs = 10000

    results = []
    for sz in msg_sizes:
        print(f"  {sz}B × {n_msgs} messages ...")
        try:
            r = await flood_proxy(host, port, n_msgs, sz)
            if "error" not in r:
                print(f"    → {r['msgs_per_sec']:.0f} msgs/sec, {r['mbps']:.1f} Mbps, {r['elapsed_s']:.2f}s")
            else:
                print(f"    → ERROR: {r['error']}")
            results.append(r)
        except Exception as e:
            print(f"    → FAILED: {e}")
            results.append({"msg_size": sz, "error": str(e)})

    # Burst test — find the ceiling
    print(f"\n  Burst test (64B × 50000) ...")
    try:
        r = await flood_proxy(host, port, 50000, 64)
        if "error" not in r:
            print(f"    → {r['msgs_per_sec']:.0f} msgs/sec (ceiling)")
        results.append(r)
    except Exception as e:
        print(f"    → FAILED: {e}")

    # Save results
    import json, csv
    out_dir = os.path.join(os.path.dirname(__file__), "results", "raw")
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, "cp_saturation.json"), "w") as f:
        json.dump(results, f, indent=2)

    valid = [r for r in results if "error" not in r]
    if valid:
        keys = sorted(set().union(*(r.keys() for r in valid)))
        with open(os.path.join(out_dir, "cp_saturation.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(valid)

    print(f"\n  Saved to {out_dir}/cp_saturation.csv")
    return results


if __name__ == "__main__":
    asyncio.run(run_saturation_test())
