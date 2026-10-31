"""Traffic-analysis resistance of the control channel (goal G5).

A passive observer on the WAN link (between the switch-side and the
controller-side proxy) records the size of every upstream burst. The
emulated switch sends a labelled stream of realistic OpenFlow messages,
spaced so that each message forms exactly one burst. The observer then tries
to infer, from burst size alone:

  task "msg_type"   the OpenFlow message type
                    (ECHO_REQUEST, PORT_STATUS, FLOW_REMOVED, MULTIPART_REPLY,
                    PACKET_IN)
  task "pkt_class"  what host traffic a PACKET_IN carries
                    (ARP, TCP SYN, DNS query, HTTP request, bulk MTU segment)

The classifier predicts the majority label observed for each burst size in
the training folds (global majority for unseen sizes). For a single discrete
feature this is the Bayes-optimal adversary, so its accuracy upper-bounds any
size-only classifier. Reported: 5-fold cross-validated accuracy, the
majority-class baseline, and mutual information I(label; size) in bits.

Run (no root needed, after channel_bench's dependencies are built):
    unshare -rn env PYTHONPATH=src python3 evaluation/traffic_analysis.py
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import shutil
import struct
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.channel_bench import (  # noqa: E402
    RESULTS, EmuSwitch, Running, _connect_one, _of, _warmup, make_tls_material,
    netns_setup, set_wan, start_config,
)

CONFIGS = ["plain", "tls_classical", "pqtls_l5", "proposed",
           "proposed_pad1024", "proposed_pad2048"]

# Inner host packets carried by PACKET_IN: (label, Ethernet frame length range)
PKT_CLASSES = [
    ("arp", (42, 42)),
    ("tcp_syn", (74, 78)),
    ("dns_query", (70, 130)),
    ("http_request", (350, 700)),
    ("bulk_segment", (1400, 1514)),
]


def _ofp_port(no: int) -> bytes:
    return (struct.pack("!I4x6s2x16sIIIIIIII", no, b"\x02\x00\x00\x00\x00" + bytes([no]),
                        f"s1-eth{no}".encode().ljust(16, b"\0"), 0, 0, 0x840, 0, 0, 0,
                        10_000_000, 10_000_000))


def msg_echo(rng) -> bytes:
    return _of(2, b"")


def msg_port_status(rng) -> bytes:
    return _of(12, struct.pack("!B7x", rng.choice([0, 1, 2])) + _ofp_port(rng.randint(1, 4)))


def msg_flow_removed(rng) -> bytes:
    match = struct.pack("!HH", 1, 12) + struct.pack("!HBBI", 0x8000, 0, 4, 1) + b"\0" * 4
    body = struct.pack("!QHBBIIHHQQ", 0, 1, 0, 0, 10, 0, 0, 0,
                       rng.randint(1, 1000), rng.randint(64, 10 ** 6)) + match
    return _of(11, body)


def msg_port_stats(rng) -> bytes:
    n = rng.randint(1, 6)
    # ofp_port_stats: port_no, pad, 12 x u64 counters, duration_sec/nsec (112 B)
    stats = b"".join(struct.pack("!I4x" + "Q" * 12 + "II", i + 1, *([0] * 12), 0, 0)
                     for i in range(n))
    return _of(19, struct.pack("!HH4x", 4, 0) + stats)


def msg_packet_in(rng, cls: str) -> bytes:
    lo, hi = dict(PKT_CLASSES)[cls]
    eth_len = rng.randint(lo, hi)
    eth = (b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01"
           + (b"\x08\x06" if cls == "arp" else b"\x08\x00")
           + b"\0" * (eth_len - 14))
    match = struct.pack("!HH", 1, 12) + struct.pack("!HBBI", 0x8000, 0, 4, 1) + b"\0" * 4
    return _of(10, struct.pack("!IHBBQ", 0xFFFFFFFF, len(eth), 0, 0, 0)
               + match + b"\0\0" + eth)


MSG_TYPES = {
    "echo_request": msg_echo,
    "port_status": msg_port_status,
    "flow_removed": msg_flow_removed,
    "multipart_reply": msg_port_stats,
    "packet_in": None,
}


class BurstSniffer:
    """Records (timestamp, payload) of upstream TCP segments to the WAN port."""

    def __init__(self, port: int) -> None:
        import socket as _s
        import threading
        self.port = port
        self.segments: list = []
        self._sock = _s.socket(_s.AF_PACKET, _s.SOCK_RAW, _s.ntohs(0x0003))
        self._sock.bind(("lo", 0))
        self._sock.settimeout(0.2)
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self) -> None:
        while not self._stop:
            try:
                pkt, addr = self._sock.recvfrom(70000)
            except OSError:
                continue
            if addr[2] != 4 or len(pkt) < 34 or pkt[12:14] != b"\x08\x00":
                continue
            ip = pkt[14:]
            if ip[9] != 6:
                continue
            ihl = (ip[0] & 0x0F) * 4
            total = struct.unpack_from("!H", ip, 2)[0]
            tcp = ip[ihl:]
            dport = struct.unpack_from("!H", tcp, 2)[0]
            payload = total - ihl - (tcp[12] >> 4) * 4
            if dport == self.port and payload > 0:
                self.segments.append((time.monotonic(), payload))

    def stop(self) -> list:
        self._stop = True
        self._t.join()
        self._sock.close()
        return self.segments


def bursts(segments: list, gap: float) -> list:
    """Group segments separated by less than `gap` seconds into bursts."""
    out, cur, last = [], 0, None
    for t, n in segments:
        if last is not None and t - last > gap:
            out.append(cur)
            cur = 0
        cur += n
        last = t
    if cur:
        out.append(cur)
    return out


def bayes_size_classifier(labels: list, sizes: list, folds: int = 5, seed: int = 1) -> dict:
    idx = list(range(len(labels)))
    random.Random(seed).shuffle(idx)
    correct = 0
    for f in range(folds):
        test = set(idx[f::folds])
        table = defaultdict(Counter)
        overall = Counter()
        for i in idx:
            if i not in test:
                table[sizes[i]][labels[i]] += 1
                overall[labels[i]] += 1
        fallback = overall.most_common(1)[0][0]
        for i in test:
            pred = table[sizes[i]].most_common(1)[0][0] if sizes[i] in table else fallback
            correct += pred == labels[i]
    n = len(labels)
    p_lab = Counter(labels)
    h = -sum(c / n * math.log2(c / n) for c in p_lab.values())
    joint = Counter(zip(sizes, labels))
    p_size = Counter(sizes)
    h_cond = -sum(c / n * math.log2(c / p_size[s]) for (s, _), c in joint.items())
    return {"accuracy": correct / n, "majority_baseline": p_lab.most_common(1)[0][1] / n,
            "chance": 1 / len(p_lab), "mutual_info_bits": h - h_cond, "label_entropy_bits": h,
            "distinct_sizes": len(p_size), "n": n}


async def _send_stream(sw: EmuSwitch, plan: list, rng, spacing: float) -> None:
    for task, label in plan:
        if task == "msg_type":
            data = (msg_packet_in(rng, rng.choice([c for c, _ in PKT_CLASSES]))
                    if label == "packet_in" else MSG_TYPES[label](rng))
        else:
            data = msg_packet_in(rng, label)
        await sw.send(data)
        await asyncio.sleep(spacing)


def run_config(cfg: str, n_per_task: int, spacing: float, seed: int) -> dict:
    rng = random.Random(seed)
    work = Path(tempfile.mkdtemp(prefix=f"ta_{cfg}_"))
    if not (cfg == "plain" or cfg.startswith("proposed")):
        make_tls_material(work)
    set_wan(0, 0)
    run = start_config(cfg, work)
    out = {}
    try:
        _warmup(run)
        for task in ("msg_type", "pkt_class"):
            labels = (list(MSG_TYPES) if task == "msg_type" else [c for c, _ in PKT_CLASSES])
            plan = [(task, rng.choice(labels)) for _ in range(n_per_task)]

            async def go():
                t, sw = await _connect_one(run.switch_port, 30)
                await asyncio.sleep(0.5)
                sniff = BurstSniffer(run.wan_port)
                await asyncio.sleep(0.2)
                await _send_stream(sw, plan, rng, spacing)
                await asyncio.sleep(0.3)
                segs = sniff.stop()
                sw.close()
                return segs

            segs = asyncio.run(go())
            sizes = bursts(segs, gap=spacing / 2)
            if len(sizes) != len(plan):
                out[task] = {"error": f"burst count {len(sizes)} != messages {len(plan)}"}
                continue
            res = bayes_size_classifier([lab for _, lab in plan], sizes)
            res["mean_wire_bytes"] = sum(sizes) / len(sizes)
            out[task] = res
            print(f"[ta] {cfg:14s} {task:9s} acc={res['accuracy']:.3f} "
                  f"(majority {res['majority_baseline']:.3f}) MI={res['mutual_info_bits']:.2f}/"
                  f"{res['label_entropy_bits']:.2f} bits sizes={res['distinct_sizes']} "
                  f"wire={res['mean_wire_bytes']:.0f}B/msg", flush=True)
    finally:
        run.stop()
        shutil.rmtree(work, ignore_errors=True)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--configs", default=",".join(CONFIGS))
    ap.add_argument("--n", type=int, default=1000, help="messages per task")
    ap.add_argument("--spacing", type=float, default=0.02, help="seconds between messages")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    netns_setup()
    rows = []
    for cfg in args.configs.split(","):
        r = run_config(cfg, args.n, args.spacing, args.seed)
        rows.append({"config": cfg, **r})
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / "traffic_analysis.json"
    path.write_text(json.dumps(rows, indent=1))
    print("→", path)


if __name__ == "__main__":
    main()
