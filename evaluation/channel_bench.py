"""Control-channel benchmark: proposed proxy vs plaintext, classical TLS 1.3
and standard post-quantum TLS 1.3 (OpenSSL 3.5), under emulated WAN
conditions.

Topology (all on loopback inside an unprivileged network namespace):

    emulated OF1.3 switches ──▶ switch-side proxy ══[WAN]══▶ controller-side proxy ──▶ Ryu

Only the WAN hop (the inter-proxy link, or switch→Ryu for plaintext) is
shaped with tc/netem, selected by TCP port, so local endpoint hops are not
penalised. lo MTU is set to 1500 so TCP segmentation and the initial
congestion window behave as on a real link.

Configurations
    plain           OVS→Ryu plaintext TCP (no proxy)
    tls_classical   stunnel pair, TLS 1.3, X25519 + ECDSA P-256 certificate
    pqtls_hybrid    stunnel pair, TLS 1.3, X25519MLKEM768 + ML-DSA-65 certificate
    pqtls_l5        stunnel pair, TLS 1.3, MLKEM1024 + ML-DSA-87 certificate
    proposed        sw_proxy_async + ctrl_proxy, ML-KEM-1024 + ML-DSA-87 (pinned)

The controller is unmodified Ryu running ryu.app.simple_switch_13.

Run (no root needed):
    unshare -rn env PYTHONPATH=src python3 evaluation/channel_bench.py --exp all
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import psutil
import yaml

ROOT = Path(__file__).resolve().parents[1]
VENV_BIN = Path(sys.executable).parent
OPT = Path(os.environ.get("PQC_OPT_DIR", ROOT.parent / "opt"))
OPENSSL_BIN = OPT / "openssl-3.5" / "bin" / "openssl"
STUNNEL_BIN = OPT / "stunnel" / "bin" / "stunnel"
RESULTS = ROOT / "evaluation" / "results" / "channel"

PORT_RYU, PORT_WAN, PORT_SW = 6653, 6652, 6634

CONFIGS = ["plain", "tls_classical", "pqtls_hybrid", "pqtls_l5", "pqtls_l5_chain", "proposed"]

TLS_PROFILES = {
    # name: (groups, certificate key algorithm)
    "tls_classical": ("X25519", "EC"),
    "pqtls_hybrid": ("X25519MLKEM768", "ML-DSA-65"),
    "pqtls_l5": ("MLKEM1024", "ML-DSA-87"),
    # Same as pqtls_l5 but with a realistic root → intermediate → leaf PKI; the
    # server sends leaf + intermediate.
    "pqtls_l5_chain": ("MLKEM1024", "ML-DSA-87"),
}


# ═════════════════════════════════════════════════════════════════════════════
# Network shaping
# ═════════════════════════════════════════════════════════════════════════════

def _sh(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)


def netns_setup() -> None:
    _sh("ip link set lo up")
    _sh("ip link set lo mtu 1500")


def set_wan(rtt_ms: float, loss_pct: float, port: int = PORT_WAN) -> None:
    """Shape packets to/from `port` on lo: one-way delay rtt/2 each direction."""
    _sh("tc qdisc del dev lo root", check=False)
    if rtt_ms <= 0 and loss_pct <= 0:
        return
    _sh("tc qdisc add dev lo root handle 1: prio bands 3 "
        "priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1")
    netem = f"tc qdisc add dev lo parent 1:3 handle 30: netem limit 100000"
    if rtt_ms > 0:
        netem += f" delay {rtt_ms / 2:.3f}ms"
    if loss_pct > 0:
        netem += f" loss {loss_pct}%"
    _sh(netem)
    for d in ("dport", "sport"):
        _sh(f"tc filter add dev lo parent 1:0 protocol ip prio 1 u32 "
            f"match ip {d} {port} 0xffff flowid 1:3")


# ═════════════════════════════════════════════════════════════════════════════
# Configuration launchers
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Running:
    name: str
    switch_port: int
    wan_port: int
    ctrl_procs: List[subprocess.Popen] = field(default_factory=list)
    sw_procs: List[subprocess.Popen] = field(default_factory=list)

    def all(self):
        return self.ctrl_procs + self.sw_procs

    def cpu_seconds(self, side: str) -> float:
        procs = self.ctrl_procs if side == "ctrl" else self.sw_procs
        total = 0.0
        for p in procs:
            try:
                t = psutil.Process(p.pid).cpu_times()
                total += t.user + t.system
            except psutil.NoSuchProcess:
                pass
        return total

    def stop(self) -> None:
        for p in self.all():
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for p in self.all():
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


def _wait_port(port: int, timeout: float = 20.0) -> None:
    import socket
    t0 = time.time()
    while time.time() - t0 < timeout:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"port {port} did not open")


def _spawn(cmd: List[str], log: Path, env: Optional[dict] = None) -> subprocess.Popen:
    fh = open(log, "w")
    return subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT,
                            env={**os.environ, **(env or {})})


def start_ryu(work: Path) -> subprocess.Popen:
    p = _spawn([str(VENV_BIN / "ryu-manager"), "--ofp-tcp-listen-port", str(PORT_RYU),
                "ryu.app.simple_switch_13"], work / "ryu.log")
    _wait_port(PORT_RYU)
    return p


def make_tls_material(work: Path) -> None:
    """CA + server certificate for every TLS profile (OpenSSL 3.5)."""
    os_ = f"LD_LIBRARY_PATH={OPENSSL_BIN.parent.parent / 'lib'} {OPENSSL_BIN}"
    for name, (_, alg) in TLS_PROFILES.items():
        d = work / name
        d.mkdir(exist_ok=True)
        if alg == "EC":
            gen = "-algorithm EC -pkeyopt ec_paramgen_curve:P-256"
        else:
            gen = f"-algorithm {alg}"
        _sh(f"{os_} genpkey {gen} -out {d}/ca.key")
        _sh(f"{os_} req -x509 -new -key {d}/ca.key -subj /CN=pqc-sdn-ca -days 30 -out {d}/ca.crt")
        issuer_crt, issuer_key = f"{d}/ca.crt", f"{d}/ca.key"
        if name.endswith("_chain"):
            _sh(f"{os_} genpkey {gen} -out {d}/int.key")
            _sh(f"{os_} req -new -key {d}/int.key -subj /CN=pqc-sdn-intermediate "
                f"-addext basicConstraints=critical,CA:TRUE "
                f"-addext keyUsage=critical,keyCertSign -out {d}/int.csr")
            _sh(f"{os_} x509 -req -in {d}/int.csr -CA {d}/ca.crt -CAkey {d}/ca.key "
                f"-CAcreateserial -copy_extensions copyall -days 30 -out {d}/int.crt")
            issuer_crt, issuer_key = f"{d}/int.crt", f"{d}/int.key"
        _sh(f"{os_} genpkey {gen} -out {d}/srv.key")
        _sh(f"{os_} req -new -key {d}/srv.key -subj /CN=ctrl -out {d}/srv.csr")
        _sh(f"{os_} x509 -req -in {d}/srv.csr -CA {issuer_crt} -CAkey {issuer_key} "
            f"-CAcreateserial -days 30 -out {d}/leaf.crt")
        chain = Path(f"{d}/leaf.crt").read_text()
        if name.endswith("_chain"):
            chain += Path(f"{d}/int.crt").read_text()
        Path(f"{d}/srv.crt").write_text(chain)


def start_tls(name: str, work: Path) -> Running:
    groups, _ = TLS_PROFILES[name]
    d = work / name
    common = ("foreground = yes\npid =\ndebug = warning\nsslVersionMin = TLSv1.3\n"
              f"curves = {groups}\n")
    srv = d / "srv.conf"
    srv.write_text(common + f"output = {d}/stunnel_srv.log\n[ctrl]\n"
                   f"accept = 127.0.0.1:{PORT_WAN}\nconnect = 127.0.0.1:{PORT_RYU}\n"
                   f"cert = {d}/srv.crt\nkey = {d}/srv.key\n"
                   # Full handshakes only: every switch is a distinct device, so no
                   # session resumption across switches.
                   "options = NO_TICKET\nsessionResume = no\n")
    cli = d / "cli.conf"
    cli.write_text(common + f"output = {d}/stunnel_cli.log\n[sw]\nclient = yes\n"
                   f"accept = 127.0.0.1:{PORT_SW}\nconnect = 127.0.0.1:{PORT_WAN}\n"
                   f"CAfile = {d}/ca.crt\nverifyChain = yes\ncheckHost = ctrl\n"
                   "sessionResume = no\n")
    ps = _spawn([str(STUNNEL_BIN), str(srv)], d / "srv.out")
    _wait_port(PORT_WAN)
    pc = _spawn([str(STUNNEL_BIN), str(cli)], d / "cli.out")
    _wait_port(PORT_SW)
    return Running(name, PORT_SW, PORT_WAN, ctrl_procs=[ps], sw_procs=[pc])


def start_proposed(work: Path, kem: str = "ML-KEM-1024", padding: int = 256) -> Running:
    cfg = yaml.safe_load((ROOT / "config" / "default.yaml").read_text())
    cfg["logging"]["level"] = "WARNING"
    cfg["crypto"]["control_plane_kem"] = kem
    cfg["crypto"]["padding_block_size"] = padding
    cfg["adaptive"]["enabled"] = False
    cfg["proxy"].update({
        "listen_host": "127.0.0.1", "base_data_port": PORT_SW,
        "controller_host": "127.0.0.1", "controller_port": PORT_WAN,
        "ctrl_proxy_port": PORT_WAN, "ryu_port": PORT_RYU,
    })
    path = work / "proposed.yaml"
    path.write_text(yaml.safe_dump(cfg))
    env = {"PQC_SDN_CONFIG": str(path), "PYTHONPATH": str(ROOT / "src"),
           "PQC_OVERRIDE_FILE": str(work / "cipher_override")}
    py = str(sys.executable)
    pc = _spawn([py, "-m", "pqc_sdn.apps.ctrl_proxy"], work / "ctrl_proxy.log", env)
    _wait_port(PORT_WAN)
    ps = _spawn([py, "-m", "pqc_sdn.apps.sw_proxy_async"], work / "sw_proxy.log", env)
    _wait_port(PORT_SW)
    return Running("proposed", PORT_SW, PORT_WAN, ctrl_procs=[pc], sw_procs=[ps])


def start_config(name: str, work: Path) -> Running:
    ryu = start_ryu(work)
    if name == "plain":
        run = Running(name, PORT_RYU, PORT_RYU)
    elif name == "proposed":
        run = start_proposed(work)
    elif name.startswith("proposed_pad"):
        run = start_proposed(work, padding=int(name[len("proposed_pad"):]))
        run.name = name
    else:
        run = start_tls(name, work)
    run.ctrl_procs.insert(0, ryu)
    return run


# ═════════════════════════════════════════════════════════════════════════════
# Emulated OpenFlow 1.3 switch
# ═════════════════════════════════════════════════════════════════════════════

OFP_HELLO, OFP_ECHO_REQ, OFP_ECHO_REP = 0, 2, 3
OFP_FEATURES_REQ, OFP_FEATURES_REP = 5, 6
OFP_GET_CONFIG_REQ, OFP_GET_CONFIG_REP = 7, 8
OFP_PACKET_IN, OFP_PACKET_OUT, OFP_FLOW_MOD = 10, 13, 14
OFP_MP_REQ, OFP_MP_REP, OFP_BARRIER_REQ, OFP_BARRIER_REP = 18, 19, 20, 21


def _of(t: int, body: bytes = b"", xid: int = 0) -> bytes:
    return struct.pack("!BBHI", 4, t, 8 + len(body), xid) + body


def _mac(n: int) -> bytes:
    return struct.pack("!H", 0x0200) + struct.pack("!I", n & 0xFFFFFFFF)


def packet_in(in_port: int, src: int, dst: int, dscp: int = 0, payload: int = 64) -> bytes:
    udp = struct.pack("!HHHH", 5000, 6000, 8 + payload, 0) + b"\x00" * payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, 20 + len(udp), 0, 0, 64, 17, 0,
                     struct.pack("!I", 0x0A000000 | (src & 0xFFFF)),
                     struct.pack("!I", 0x0A000000 | (dst & 0xFFFF))) + udp
    eth = _mac(dst) + _mac(src) + b"\x08\x00" + ip
    match = struct.pack("!HH", 1, 12) + struct.pack("!HBBI", 0x8000, 0, 4, in_port) + b"\x00" * 4
    body = struct.pack("!IHBBQ", 0xFFFFFFFF, len(eth), 0, 0, 0) + match + b"\x00\x00" + eth
    return _of(OFP_PACKET_IN, body)


class EmuSwitch:
    """Minimal OF1.3 switch: completes the Ryu handshake and answers
    controller requests; counts FLOW_MOD / PACKET_OUT responses."""

    def __init__(self, dpid: int, port: int, host: str = "127.0.0.1") -> None:
        self.dpid = dpid
        self.port = port
        self.host = host
        self.ready = asyncio.Event()
        self.packet_outs = 0
        self.flow_mods = 0
        self.po_event = asyncio.Event()
        self.reader = self.writer = None

    async def connect(self) -> float:
        """Connect and wait until Ryu installs the table-miss entry.
        Returns time-to-ready in ms."""
        t0 = time.perf_counter()
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.writer.write(_of(OFP_HELLO))
        await self.writer.drain()
        self._task = asyncio.ensure_future(self._loop())
        await self.ready.wait()
        return (time.perf_counter() - t0) * 1000

    async def _loop(self) -> None:
        buf = b""
        try:
            while True:
                chunk = await self.reader.read(65536)
                if not chunk:
                    return
                buf += chunk
                while len(buf) >= 8:
                    n = struct.unpack_from("!H", buf, 2)[0]
                    if len(buf) < n:
                        break
                    msg, buf = buf[:n], buf[n:]
                    self._handle(msg)
        except (ConnectionError, asyncio.CancelledError):
            return

    def _handle(self, msg: bytes) -> None:
        t, xid = msg[1], struct.unpack_from("!I", msg, 4)[0]
        w = self.writer
        if t == OFP_FEATURES_REQ:
            w.write(_of(OFP_FEATURES_REP,
                        struct.pack("!QIBBHII", self.dpid, 256, 254, 0, 0, 0x4F, 0), xid))
        elif t == OFP_ECHO_REQ:
            w.write(_of(OFP_ECHO_REP, msg[8:], xid))
        elif t == OFP_MP_REQ:
            mp_type = struct.unpack_from("!H", msg, 8)[0]
            w.write(_of(OFP_MP_REP, struct.pack("!HHI", mp_type, 0, 0), xid))
        elif t == OFP_BARRIER_REQ:
            w.write(_of(OFP_BARRIER_REP, b"", xid))
        elif t == OFP_GET_CONFIG_REQ:
            w.write(_of(OFP_GET_CONFIG_REP, struct.pack("!HH", 0, 0xFFFF), xid))
        elif t == OFP_FLOW_MOD:
            self.flow_mods += 1
            self.ready.set()            # simple_switch_13 table-miss → registered
        elif t == OFP_PACKET_OUT:
            self.packet_outs += 1
            self.po_event.set()

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    def close(self) -> None:
        if self.writer:
            self.writer.close()
        if getattr(self, "_task", None):
            self._task.cancel()


# ═════════════════════════════════════════════════════════════════════════════
# Experiments
# ═════════════════════════════════════════════════════════════════════════════

def _stats(xs: List[float]) -> dict:
    if not xs:
        return {"n": 0}
    xs = sorted(xs)
    q = lambda p: xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))]
    return {"n": len(xs), "mean": statistics.fmean(xs), "std": statistics.pstdev(xs),
            "p50": q(0.5), "p95": q(0.95), "p99": q(0.99), "max": xs[-1]}


_dpid_counter = 1


def _next_dpid() -> int:
    global _dpid_counter
    _dpid_counter += 1
    return _dpid_counter


async def _connect_one(port: int, timeout: float,
                       host: str = "127.0.0.1") -> Tuple[Optional[float], EmuSwitch]:
    sw = EmuSwitch(_next_dpid(), port, host)
    try:
        return await asyncio.wait_for(sw.connect(), timeout), sw
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return None, sw


async def exp_connect_sequential(run: Running, n: int, timeout: float) -> dict:
    """n sequential fresh switch connections; time-to-ready each."""
    times, fails = [], 0
    for _ in range(n):
        t, sw = await _connect_one(run.switch_port, timeout)
        sw.close()
        if t is None:
            fails += 1
        else:
            times.append(t)
        await asyncio.sleep(0.05)
    return {"ready_ms": _stats(times), "failures": fails, "samples": times}


async def exp_storm(run: Running, n_switches: int, timeout: float) -> dict:
    """All switches connect at once (controller restart / mass reconnection)."""
    c0, s0, t0 = run.cpu_seconds("ctrl"), run.cpu_seconds("sw"), time.perf_counter()
    res = await asyncio.gather(*[_connect_one(run.switch_port, timeout)
                                 for _ in range(n_switches)])
    wall = time.perf_counter() - t0
    times = [t for t, _ in res if t is not None]
    for _, sw in res:
        sw.close()
    return {"n_switches": n_switches, "all_ready_s": (max(times) / 1000) if times else None,
            "wall_s": wall, "ready_ms": _stats(times),
            "failures": n_switches - len(times),
            "ctrl_cpu_s": run.cpu_seconds("ctrl") - c0,
            "sw_cpu_s": run.cpu_seconds("sw") - s0}


async def exp_arrival(run: Running, n_switches: int, rate: float, timeout: float) -> dict:
    """Switches arrive at `rate`/s (Poisson); per-switch time-to-ready and
    controller-side CPU utilisation during the arrival window."""
    c0, t0 = run.cpu_seconds("ctrl"), time.perf_counter()
    tasks, rng = [], random.Random(n_switches * 1000 + int(rate))
    for _ in range(n_switches):
        tasks.append(asyncio.ensure_future(_connect_one(run.switch_port, timeout)))
        await asyncio.sleep(rng.expovariate(rate))
    res = await asyncio.gather(*tasks)
    wall = time.perf_counter() - t0
    times = [t for t, _ in res if t is not None]
    for _, sw in res:
        sw.close()
    cpu = run.cpu_seconds("ctrl") - c0
    return {"n_switches": n_switches, "rate": rate, "ready_ms": _stats(times),
            "failures": n_switches - len(times), "ctrl_cpu_s": cpu,
            "ctrl_cpu_pct": 100 * cpu / wall, "wall_s": wall}


async def exp_flow_setup(run: Running, n_switches: int, duration: float,
                         window: int, dscp_mix: List[int]) -> dict:
    """cbench-style flow setup through the channel.

    Each switch first teaches the controller a destination MAC, then sends
    PACKET_INs from fresh source MACs to it; simple_switch_13 answers each
    with FLOW_MOD + PACKET_OUT. window=1 → latency mode; window>1 →
    throughput mode (that many PACKET_INs outstanding per switch).
    """
    sws = []
    for _ in range(n_switches):
        t, sw = await _connect_one(run.switch_port, 30)
        if t is not None:
            sws.append(sw)
    c0 = run.cpu_seconds("ctrl")
    lat: List[float] = []
    stop_at = time.perf_counter() + duration

    async def drive(sw: EmuSwitch, k: int) -> int:
        dst = 0xD000 + k
        await sw.send(packet_in(2, dst, 0xFFFF))       # learn dst on port 2
        await asyncio.sleep(0.2)
        base, src, sent = sw.packet_outs, 0x10000 * (k + 1), 0
        while time.perf_counter() < stop_at:
            burst = []
            for _ in range(window):
                src += 1
                burst.append(packet_in(1, src, dst, dscp=dscp_mix[src % len(dscp_mix)]))
            target = sw.packet_outs + window
            t0 = time.perf_counter()
            sw.writer.write(b"".join(burst))
            await sw.writer.drain()
            sent += window
            while sw.packet_outs < target and time.perf_counter() < stop_at + 2:
                sw.po_event.clear()
                try:
                    await asyncio.wait_for(sw.po_event.wait(), 2)
                except asyncio.TimeoutError:
                    break
            if window == 1 and sw.packet_outs >= target:
                lat.append((time.perf_counter() - t0) * 1000)
        return sw.packet_outs - base

    t0 = time.perf_counter()
    done = await asyncio.gather(*[drive(sw, i) for i, sw in enumerate(sws)])
    wall = time.perf_counter() - t0
    for sw in sws:
        sw.close()
    return {"n_switches": len(sws), "window": window, "responses": sum(done),
            "flows_per_s": sum(done) / wall, "latency_ms": _stats(lat),
            "ctrl_cpu_pct": 100 * (run.cpu_seconds("ctrl") - c0) / wall}


# ═════════════════════════════════════════════════════════════════════════════
# Drivers
# ═════════════════════════════════════════════════════════════════════════════

def _save(name: str, rows: list) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"{name}.json"
    path.write_text(json.dumps(rows, indent=1))
    return path


def _warmup(run: Running, n: int = 3) -> None:
    """Untimed connections so one-time costs (imports, library init, first
    thread-pool spin-up) are excluded equally for every configuration."""
    async def go():
        for _ in range(n):
            t, sw = await _connect_one(run.switch_port, 30)
            sw.close()
            await asyncio.sleep(0.05)
    asyncio.run(go())


def _with_config(name: str, work: Path, coro_factory):
    run = start_config(name, work)
    try:
        time.sleep(1.0)
        return asyncio.run(coro_factory(run))
    finally:
        run.stop()
        time.sleep(0.5)


def drive_rtt(configs, reps, n_conn, grid) -> list:
    rows = []
    for cfg in configs:
        for rtt, loss in grid:
            for rep in range(reps):
                work = Path(tempfile.mkdtemp(prefix=f"cb_{cfg}_"))
                if cfg != "plain" and cfg != "proposed":
                    make_tls_material(work)
                set_wan(0, 0)
                run = start_config(cfg, work)
                try:
                    _warmup(run)
                    set_wan(rtt, loss, run.wan_port)
                    time.sleep(0.5)
                    r = asyncio.run(exp_connect_sequential(run, n_conn, timeout=30))
                finally:
                    set_wan(0, 0)
                    run.stop()
                    shutil.rmtree(work, ignore_errors=True)
                r.update({"config": cfg, "rtt_ms": rtt, "loss_pct": loss, "rep": rep})
                rows.append(r)
                print(f"[rtt] {cfg:14s} rtt={rtt:>5}ms loss={loss}% rep={rep} "
                      f"ready p50={r['ready_ms'].get('p50', float('nan')):.1f}ms "
                      f"fail={r['failures']}", flush=True)
    return rows


class WanSniffer:
    """Counts TCP payload bytes/packets to and from the WAN port on lo.

    Uses an AF_PACKET socket (allowed inside the network namespace); on lo
    every packet is seen once as PACKET_OUTGOING, which is all we count.
    """

    def __init__(self, port: int) -> None:
        import socket as _s
        import threading
        self.port = port
        self.c = {"bytes_up": 0, "bytes_down": 0, "pkts_up": 0, "pkts_down": 0}
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
                continue                       # PACKET_OUTGOING IPv4 only
            ip = pkt[14:]
            if ip[9] != 6:
                continue
            ihl = (ip[0] & 0x0F) * 4
            total = struct.unpack_from("!H", ip, 2)[0]
            tcp = ip[ihl:]
            sport, dport = struct.unpack_from("!HH", tcp, 0)
            payload = total - ihl - (tcp[12] >> 4) * 4
            if dport == self.port:
                self.c["bytes_up"] += payload
                self.c["pkts_up"] += 1
            elif sport == self.port:
                self.c["bytes_down"] += payload
                self.c["pkts_down"] += 1

    def stop(self) -> dict:
        self._stop = True
        self._t.join()
        self._sock.close()
        return dict(self.c)


def _capture_one_connection(run: Running) -> dict:
    """Wire bytes/packets on the WAN port for one switch connection, up to
    the point the switch is registered (handshake + OpenFlow setup)."""
    sniff = WanSniffer(run.wan_port)
    time.sleep(0.2)

    async def one():
        t, sw = await _connect_one(run.switch_port, 30)
        sw.close()
        return t
    t = asyncio.run(one())
    time.sleep(0.3)
    return {"ready_ms": t, **sniff.stop()}


def drive_wire(configs, reps) -> list:
    rows = []
    for cfg in configs:
        work = Path(tempfile.mkdtemp(prefix=f"cb_{cfg}_"))
        if cfg not in ("plain", "proposed"):
            make_tls_material(work)
        set_wan(0, 0)
        run = start_config(cfg, work)
        try:
            _warmup(run)
            for rep in range(reps):
                r = _capture_one_connection(run)
                r.update({"config": cfg, "rep": rep})
                rows.append(r)
            print(f"[wire] {cfg:14s} up={r['bytes_up']}B/{r['pkts_up']}pk "
                  f"down={r['bytes_down']}B/{r['pkts_down']}pk", flush=True)
        finally:
            run.stop()
            shutil.rmtree(work, ignore_errors=True)
    return rows


def drive_storm(configs, reps, sizes, rtt) -> list:
    rows = []
    for cfg in configs:
        for n in sizes:
            for rep in range(reps):
                work = Path(tempfile.mkdtemp(prefix=f"cb_{cfg}_"))
                if cfg not in ("plain", "proposed"):
                    make_tls_material(work)
                set_wan(0, 0)
                run = start_config(cfg, work)
                try:
                    _warmup(run)
                    set_wan(rtt, 0, run.wan_port)
                    time.sleep(0.5)
                    r = asyncio.run(exp_storm(run, n, timeout=120))
                finally:
                    set_wan(0, 0)
                    run.stop()
                    shutil.rmtree(work, ignore_errors=True)
                r.update({"config": cfg, "rtt_ms": rtt, "rep": rep})
                rows.append(r)
                print(f"[storm] {cfg:14s} n={n:>3} rep={rep} all_ready={r['all_ready_s']}s "
                      f"ctrl_cpu={r['ctrl_cpu_s']:.2f}s fail={r['failures']}", flush=True)
    return rows


def drive_arrival(configs, reps, n, rates, rtt) -> list:
    rows = []
    for cfg in configs:
        for rate in rates:
            for rep in range(reps):
                work = Path(tempfile.mkdtemp(prefix=f"cb_{cfg}_"))
                if cfg not in ("plain", "proposed"):
                    make_tls_material(work)
                set_wan(0, 0)
                run = start_config(cfg, work)
                try:
                    _warmup(run)
                    set_wan(rtt, 0, run.wan_port)
                    time.sleep(0.5)
                    r = asyncio.run(exp_arrival(run, n, rate, timeout=120))
                finally:
                    set_wan(0, 0)
                    run.stop()
                    shutil.rmtree(work, ignore_errors=True)
                r.update({"config": cfg, "rtt_ms": rtt, "rep": rep})
                rows.append(r)
                print(f"[arrival] {cfg:14s} R={rate:>4}/s rep={rep} "
                      f"ready p50={r['ready_ms'].get('p50', float('nan')):.1f}ms "
                      f"cpu={r['ctrl_cpu_pct']:.1f}%", flush=True)
    return rows


def drive_flow(configs, reps, n_sw, duration, windows, rtt) -> list:
    rows = []
    mix = [46, 10, 0]   # EF, AF11, BE → ChaCha20 / AES-256 / AES-128 in proposed
    for cfg in configs:
        for window in windows:
            for rep in range(reps):
                work = Path(tempfile.mkdtemp(prefix=f"cb_{cfg}_"))
                if cfg not in ("plain", "proposed"):
                    make_tls_material(work)
                set_wan(0, 0)
                run = start_config(cfg, work)
                try:
                    _warmup(run)
                    set_wan(rtt, 0, run.wan_port)
                    time.sleep(0.5)
                    r = asyncio.run(exp_flow_setup(run, n_sw, duration, window, mix))
                finally:
                    set_wan(0, 0)
                    run.stop()
                    shutil.rmtree(work, ignore_errors=True)
                r.update({"config": cfg, "rtt_ms": rtt, "rep": rep})
                rows.append(r)
                print(f"[flow] {cfg:14s} W={window:>3} rep={rep} "
                      f"{r['flows_per_s']:.0f} flows/s lat p50="
                      f"{r['latency_ms'].get('p50', float('nan')):.2f}ms", flush=True)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", default="all", help="wire,rtt,storm,arrival,flow or all")
    ap.add_argument("--configs", default=",".join(CONFIGS))
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--quick", action="store_true", help="tiny smoke run")
    args = ap.parse_args()
    netns_setup()
    configs = args.configs.split(",")
    exps = (["wire", "rtt", "storm", "arrival", "flow"] if args.exp == "all"
            else args.exp.split(","))
    q = args.quick
    reps = 1 if q else args.reps

    if "wire" in exps:
        print("→", _save("wire", drive_wire(configs, 3 if q else reps)))
    if "rtt" in exps:
        grid = ([(0, 0), (20, 1)] if q else
                [(0, 0), (2, 0), (10, 0), (50, 0), (100, 0), (10, 1), (10, 2), (50, 1), (50, 2)])
        print("→", _save("rtt_loss", drive_rtt(configs, reps, 3 if q else 20, grid)))
    if "storm" in exps:
        sizes = [20] if q else [20, 45, 80, 125]
        print("→", _save("storm", drive_storm(configs, reps, sizes, rtt=2)))
    if "arrival" in exps:
        rates = [10] if q else [10, 20, 30, 60]
        print("→", _save("arrival", drive_arrival(configs, reps, 20 if q else 60, rates, rtt=2)))
    if "flow" in exps:
        print("→", _save("flow_setup", drive_flow(configs, reps, 4 if q else 16,
                                                   3 if q else 10, [1, 32], rtt=2)))


if __name__ == "__main__":
    main()
