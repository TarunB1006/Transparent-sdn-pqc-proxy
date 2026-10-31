"""Control-channel benchmark on real Open vSwitch (Mininet).

    root namespace                                            netns "pqcctl"
    OVS (Mininet) ─▶ switch-side proxy ══ veth (tc netem) ══▶ controller-side proxy ─▶ Ryu

The controller side runs in its own network namespace behind a veth pair, so
tc/netem shapes only the switch↔controller link (the "WAN"); the local
OVS→proxy and proxy→Ryu hops are untouched. Ryu runs stock simple_switch_13
plus a one-line readiness probe (evaluation/ryu_apps/ready_probe.py).

Configurations
    plain            OVS → Ryu, plaintext TCP across the WAN
    tls_classical    stunnel pair, TLS 1.3, X25519, ECDSA-P256 certs (mutual)
    pqtls_hybrid     stunnel pair, TLS 1.3, X25519MLKEM768, ML-DSA-65 certs (mutual)
    pqtls_l5         stunnel pair, TLS 1.3, MLKEM1024, ML-DSA-87 certs (mutual)
    pqtls_l5_chain   as pqtls_l5 with root → intermediate → leaf chains
    proposed         sw_proxy_async + ctrl_proxy: ML-KEM-1024, ML-DSA-87,
                     pinning + mutual auth, DSCP-adaptive per-frame cipher
    proposed_aes256 / proposed_chacha   proposed with one fixed cipher
    proposed_padN    proposed with an N-byte padding block

Experiments (--exp, comma separated)
    wire     WAN bytes/packets for one switch connection
    rtt      time-to-ready under RTT/loss (sequential single-switch connects)
    storm    N switches reconnect simultaneously (N = 20..125)
    arrival  N switches arrive at rate R/s (Poisson)
    flood    new-flow flood through the channel; DSCP mix EF/AF11/BE;
             AES-NI on/off; adaptive vs fixed AES-256 vs fixed ChaCha20
    ta       traffic analysis: infer PACKET_IN host-packet class from WAN sizes

Run as root:   sudo -E bash scripts/run_channel_bench.sh [--pilot]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import random
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import psutil
import yaml

ROOT = Path(__file__).resolve().parents[1]
VENV_PY = os.environ.get("PQC_VENV_PY", sys.executable)
VENV_BIN = Path(VENV_PY).parent
OPT = Path(os.environ.get("PQC_OPT_DIR", ROOT.parent / "opt"))
OPENSSL = OPT / "openssl-3.5" / "bin" / "openssl"
OPENSSL_LIB = OPT / "openssl-3.5" / "lib"
STUNNEL = OPT / "stunnel" / "bin" / "stunnel"
RESULTS = Path(os.environ.get("PQC_MN_RESULTS", ROOT / "evaluation" / "results" / "mininet"))
WORK = Path("/tmp/pqc_mnbench")

NS = "pqcctl"
SW_IF, CTL_IF = "pqcveth-sw", "pqcveth-ctl"
SW_IP, CTL_IP = "10.250.0.1", "10.250.0.2"
PORT_RYU, PORT_WAN, PORT_LOCAL = 6653, 6652, 6634
READY_LOG = WORK / "ready.log"
NO_AESNI = "~0x200000200000000"

# CPU quota (percent of one core) for the switch-side proxy process, used to
# model a constrained switch or edge device. None = unconstrained.
SW_CPU_QUOTA: Optional[int] = None


def _sw_cmd(cmd: List[str]) -> List[str]:
    if SW_CPU_QUOTA is None:
        return cmd
    return ["systemd-run", "--scope", "--quiet", "--collect",
            "-p", f"CPUQuota={SW_CPU_QUOTA}%", "--"] + cmd

TLS_PROFILES = {
    "tls_classical": ("X25519", "EC", False),
    "pqtls_hybrid": ("X25519MLKEM768", "ML-DSA-65", False),
    "pqtls_l5": ("MLKEM1024", "ML-DSA-87", False),
    "pqtls_l5_chain": ("MLKEM1024", "ML-DSA-87", True),
}
CHANNEL_CONFIGS = ["plain", "tls_classical", "pqtls_hybrid", "pqtls_l5", "pqtls_l5_chain",
                   "proposed"]


def sh(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)


def stats(xs: List[float]) -> dict:
    if not xs:
        return {"n": 0}
    xs = sorted(xs)
    q = lambda p: xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))]
    return {"n": len(xs), "mean": statistics.fmean(xs), "std": statistics.pstdev(xs),
            "p50": q(0.5), "p95": q(0.95), "p99": q(0.99), "max": xs[-1]}


# ═════════════════════════════════════════════════════════════════════════════
# WAN namespace + shaping
# ═════════════════════════════════════════════════════════════════════════════

def wan_setup() -> None:
    wan_teardown()
    sh(f"ip netns add {NS}")
    # gso_max_segs 1: no segmentation offload, so netem delays/drops real
    # MTU-sized TCP segments rather than 64 KB super-packets.
    sh(f"ip link add {SW_IF} gso_max_segs 1 gso_max_size 1500 type veth "
       f"peer name {CTL_IF} gso_max_segs 1 gso_max_size 1500")
    sh(f"ip link set {CTL_IF} netns {NS}")
    sh(f"ip addr add {SW_IP}/30 dev {SW_IF} && ip link set {SW_IF} up")
    sh(f"ip netns exec {NS} ip addr add {CTL_IP}/30 dev {CTL_IF}")
    sh(f"ip netns exec {NS} ip link set {CTL_IF} up")
    sh(f"ip netns exec {NS} ip link set lo up")


def wan_teardown() -> None:
    sh(f"ip link del {SW_IF}", check=False)
    sh(f"ip netns del {NS}", check=False)


def set_wan(rtt_ms: float, loss_pct: float) -> None:
    for prefix, dev in (("", SW_IF), (f"ip netns exec {NS} ", CTL_IF)):
        sh(f"{prefix}tc qdisc del dev {dev} root", check=False)
        if rtt_ms > 0 or loss_pct > 0:
            args = "netem limit 100000"
            if rtt_ms > 0:
                args += f" delay {rtt_ms / 2:.3f}ms"
            if loss_pct > 0:
                args += f" loss {loss_pct}%"
            sh(f"{prefix}tc qdisc add dev {dev} root {args}")


# ═════════════════════════════════════════════════════════════════════════════
# Controller-side and switch-side stacks
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Stack:
    name: str
    target: str                       # OVS controller target
    wan_port: int
    ctrl: List[subprocess.Popen] = field(default_factory=list)
    sw: List[subprocess.Popen] = field(default_factory=list)

    def cpu(self, side: str) -> float:
        total = 0.0
        for p in (self.ctrl if side == "ctrl" else self.sw):
            try:
                t = psutil.Process(p.pid).cpu_times()
                total += t.user + t.system
            except psutil.NoSuchProcess:
                pass
        return total

    def rss_mb(self, side: str) -> float:
        total = 0.0
        for p in (self.ctrl if side == "ctrl" else self.sw):
            try:
                total += psutil.Process(p.pid).memory_info().rss / 2 ** 20
            except psutil.NoSuchProcess:
                pass
        return total

    def stop(self) -> None:
        for p in self.ctrl + self.sw:
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for p in self.ctrl + self.sw:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        time.sleep(0.5)


def _spawn(cmd: List[str], log: Path, env: Optional[dict] = None, ns: bool = False):
    if ns:
        cmd = ["ip", "netns", "exec", NS] + cmd
    return subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT,
                            env={**os.environ, **(env or {})})


def _wait_port(host: str, port: int, ns: bool = False, timeout: float = 30) -> None:
    probe = (f"{'ip netns exec ' + NS + ' ' if ns else ''}"
             f"bash -c 'exec 3<>/dev/tcp/{host}/{port}' 2>/dev/null")
    t0 = time.time()
    while time.time() - t0 < timeout:
        if sh(probe, check=False).returncode == 0:
            return
        time.sleep(0.2)
    raise RuntimeError(f"{host}:{port} did not open")


def start_ryu(work: Path) -> subprocess.Popen:
    env = {"PQC_READY_LOG": str(READY_LOG), "PATH": f"{VENV_BIN}:{os.environ['PATH']}"}
    p = _spawn([str(VENV_BIN / "ryu-manager"), "--ofp-tcp-listen-port", str(PORT_RYU),
                str(ROOT / "evaluation" / "ryu_apps" / "ready_probe.py")],
               work / "ryu.log", env, ns=True)
    _wait_port("127.0.0.1", PORT_RYU, ns=True)
    return p


def make_tls_material(name: str, work: Path) -> Path:
    """Server and client certificates from two *separate* CAs.

    Each side trusts only the other side's CA. With a shared CA, OpenSSL's
    automatic chain building would append the CA certificate from the
    verification store to the side's own Certificate message, which real
    deployments do not send. With separate CAs a side sends exactly its
    configured chain: leaf only, or leaf + intermediate for *_chain profiles.
    """
    _, alg, chain = TLS_PROFILES[name]
    d = work / name
    d.mkdir(parents=True, exist_ok=True)
    o = f"LD_LIBRARY_PATH={OPENSSL_LIB} {OPENSSL}"
    gen = "-algorithm EC -pkeyopt ec_paramgen_curve:P-256" if alg == "EC" else f"-algorithm {alg}"
    for role, cn in (("srv", "ctrl"), ("cli", "switch")):
        ca = f"{d}/{role}_ca"
        sh(f"{o} genpkey {gen} -out {ca}.key")
        sh(f"{o} req -x509 -new -key {ca}.key -subj /CN=pqc-sdn-{role}-ca -days 30 -out {ca}.crt")
        issuer = (f"{ca}.crt", f"{ca}.key")
        if chain:
            it = f"{d}/{role}_int"
            sh(f"{o} genpkey {gen} -out {it}.key")
            sh(f"{o} req -new -key {it}.key -subj /CN=pqc-sdn-{role}-int "
               f"-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign "
               f"-out {it}.csr")
            sh(f"{o} x509 -req -in {it}.csr -CA {ca}.crt -CAkey {ca}.key -CAcreateserial "
               f"-copy_extensions copyall -days 30 -out {it}.crt")
            issuer = (f"{it}.crt", f"{it}.key")
        sh(f"{o} genpkey {gen} -out {d}/{role}.key")
        sh(f"{o} req -new -key {d}/{role}.key -subj /CN={cn} -out {d}/{role}.csr")
        sh(f"{o} x509 -req -in {d}/{role}.csr -CA {issuer[0]} -CAkey {issuer[1]} "
           f"-CAcreateserial -days 30 -out {d}/{role}.leaf")
        pem = Path(f"{d}/{role}.leaf").read_text()
        if chain:
            pem += Path(f"{d}/{role}_int.crt").read_text()
        Path(f"{d}/{role}.crt").write_text(pem)
    return d


def start_tls(name: str, work: Path, env: dict) -> Stack:
    groups = TLS_PROFILES[name][0]
    d = make_tls_material(name, work)
    common = (f"foreground = yes\npid =\ndebug = warning\nsslVersionMin = TLSv1.3\n"
              f"curves = {groups}\nsessionResume = no\n")
    (d / "srv.conf").write_text(
        common + f"output = {d}/srv.log\n[ctrl]\naccept = {CTL_IP}:{PORT_WAN}\n"
        f"connect = 127.0.0.1:{PORT_RYU}\ncert = {d}/srv.crt\nkey = {d}/srv.key\n"
        f"CAfile = {d}/cli_ca.crt\nverifyChain = yes\nrequireCert = yes\noptions = NO_TICKET\n")
    (d / "cli.conf").write_text(
        common + f"output = {d}/cli.log\n[sw]\nclient = yes\naccept = 127.0.0.1:{PORT_LOCAL}\n"
        f"connect = {CTL_IP}:{PORT_WAN}\nCAfile = {d}/srv_ca.crt\nverifyChain = yes\n"
        f"checkHost = ctrl\ncert = {d}/cli.crt\nkey = {d}/cli.key\n")
    srv = _spawn([str(STUNNEL), str(d / "srv.conf")], d / "srv.out", env, ns=True)
    _wait_port(CTL_IP, PORT_WAN, ns=True)
    cli = _spawn(_sw_cmd([str(STUNNEL), str(d / "cli.conf")]), d / "cli.out", env)
    _wait_port("127.0.0.1", PORT_LOCAL)
    return Stack(name, f"tcp:127.0.0.1:{PORT_LOCAL}", PORT_WAN, ctrl=[srv], sw=[cli])


def start_proposed(name: str, work: Path, env: dict) -> Stack:
    cfg = yaml.safe_load((ROOT / "config" / "default.yaml").read_text())
    cfg["logging"]["level"] = "WARNING"
    cfg["adaptive"]["enabled"] = False
    if name.startswith("proposed_pad"):
        cfg["crypto"]["padding_block_size"] = int(name[len("proposed_pad"):])
    cfg["proxy"].update({
        "listen_host": "127.0.0.1", "base_data_port": PORT_LOCAL,
        "controller_host": CTL_IP, "controller_port": PORT_WAN,
        "ctrl_listen_host": CTL_IP, "ctrl_proxy_port": PORT_WAN, "ryu_port": PORT_RYU,
        "mutual_auth": True, "require_pinning": True,
    })
    path = work / f"{name}.yaml"
    path.write_text(yaml.safe_dump(cfg))
    penv = {**env, "PQC_SDN_CONFIG": str(path), "PYTHONPATH": str(ROOT / "src"),
            "PQC_OVERRIDE_FILE": str(work / "cipher_override")}
    fixed = {"proposed_aes256": "AES-256-GCM", "proposed_chacha": "ChaCha20-Poly1305"}.get(name)
    if fixed:
        penv["PQC_FIXED_CIPHER"] = fixed
    ctrl = _spawn([VENV_PY, "-m", "pqc_sdn.apps.ctrl_proxy"], work / f"{name}_ctrl.log",
                  penv, ns=True)
    _wait_port(CTL_IP, PORT_WAN, ns=True)
    sw = _spawn(_sw_cmd([VENV_PY, "-m", "pqc_sdn.apps.sw_proxy_async"]), work / f"{name}_sw.log", penv)
    _wait_port("127.0.0.1", PORT_LOCAL)
    return Stack(name, f"tcp:127.0.0.1:{PORT_LOCAL}", PORT_WAN, ctrl=[ctrl], sw=[sw])


def start_stack(name: str, no_aesni: bool = False) -> Stack:
    work = WORK / f"{name}{'_noaesni' if no_aesni else ''}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    env = {"OPENSSL_ia32cap": NO_AESNI} if no_aesni else {}
    ryu = start_ryu(work)
    if name == "plain":
        st = Stack(name, f"tcp:{CTL_IP}:{PORT_RYU}", PORT_RYU)
    elif name in TLS_PROFILES:
        st = start_tls(name, work, env)
    else:
        st = start_proposed(name, work, env)
    st.ctrl.insert(0, ryu)
    return st


def provision_identities() -> None:
    """Controller identity + one authorized switch-proxy identity."""
    code = ("from pqc_sdn.tls.identity import *;"
            "load_or_create_identity();"
            "authorize_switch_key(load_or_create_switch_identity().public_key)")
    subprocess.run([VENV_PY, "-c", code], check=True, env={**os.environ, "PYTHONPATH": str(ROOT / "src")})


# ═════════════════════════════════════════════════════════════════════════════
# Mininet + OVS controller control
# ═════════════════════════════════════════════════════════════════════════════

class Net:
    """Mininet network of n OVS switches (no controller) and optional hosts."""

    def __init__(self, n_switches: int, hosts: int = 0) -> None:
        from mininet.net import Mininet
        from mininet.node import OVSKernelSwitch
        from mininet.topo import Topo

        class _T(Topo):
            def build(self):
                prev = None
                for i in range(1, n_switches + 1):
                    s = self.addSwitch(f"s{i}", dpid=f"{i:016x}", protocols="OpenFlow13")
                    if prev is not None and hosts:
                        self.addLink(prev, s)
                    prev = s
                for j in range(1, hosts + 1):
                    self.addLink(self.addHost(f"h{j}"), "s1")

        self.net = Mininet(topo=_T(), controller=None, switch=OVSKernelSwitch,
                           autoSetMacs=True, build=True)
        self.net.start()
        self.switches = [s.name for s in self.net.switches]
        for s in self.switches:
            sh(f"ovs-vsctl set-fail-mode {s} secure")
        for h in self.net.hosts:   # no IPv6 ND/RS chatter in captures
            h.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1 "
                  "net.ipv6.conf.default.disable_ipv6=1")
        self.disconnect()

    def connect(self, target: str, names: Optional[List[str]] = None) -> float:
        names = names or self.switches
        cmd = "ovs-vsctl --no-wait " + " ".join(f"-- set-controller {s} {target}" for s in names)
        t0 = time.time()
        sh(cmd)
        return t0

    def disconnect(self, names: Optional[List[str]] = None) -> None:
        names = names or self.switches
        sh("ovs-vsctl " + " ".join(f"-- del-controller {s}" for s in names), check=False)

    def stop(self) -> None:
        self.net.stop()


def read_ready(since: float) -> Dict[int, float]:
    out: Dict[int, float] = {}
    if READY_LOG.exists():
        for line in READY_LOG.read_text().splitlines():
            dpid, t = line.split(",")
            t = float(t)
            if t >= since and int(dpid) not in out:
                out[int(dpid)] = t
    return out


def wait_ready(dpids: List[int], t0: float, timeout: float) -> Dict[int, float]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        got = read_ready(t0)
        if all(d in got for d in dpids):
            return got
        time.sleep(0.005)
    return read_ready(t0)


class SynSniffer:
    """Timestamps of TCP SYNs that OVS sends towards its controller target.

    OVS takes a fixed ~0.5 s between an OVSDB set-controller and opening the
    connection; timing from the SYN removes that switch-internal delay so
    the measurement covers only channel setup (TCP + security handshake +
    OpenFlow handshake). SYNs are seen on lo (OVS → local proxy) or on the
    WAN veth (OVS → Ryu directly, plaintext).
    """

    def __init__(self, target: str) -> None:
        import socket
        _, host, port = target.split(":")
        self.port = int(port)
        self.iface = "lo" if host.startswith("127.") else SW_IF
        self.times: List[float] = []
        self._s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self._s.bind((self.iface, 0))
        self._s.settimeout(0.1)
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self) -> None:
        while not self._stop:
            try:
                pkt, addr = self._s.recvfrom(256)
            except OSError:
                continue
            if self.iface == "lo" and addr[2] != 4:     # count each lo packet once
                continue
            if len(pkt) < 54 or pkt[12:14] != b"\x08\x00" or pkt[23] != 6:
                continue
            ihl = (pkt[14] & 0x0F) * 4
            tcp = 14 + ihl
            dport = struct.unpack_from("!H", pkt, tcp + 2)[0]
            if dport == self.port and pkt[tcp + 13] & 0x12 == 0x02:   # SYN, not SYN-ACK
                self.times.append(time.time())

    def stop(self) -> List[float]:
        self._stop = True
        self._t.join()
        self._s.close()
        return self.times


def reconnect_measure(net: Net, st: Stack, names: List[str], timeout: float,
                      meta: Optional[dict] = None) -> Dict[int, float]:
    """Disconnect `names`, reconnect them in one OVSDB transaction, and return
    per-dpid time-to-ready in ms, measured from the first TCP SYN that OVS
    sends (missing dpids failed within the timeout). If `meta` is given, the
    OVS-internal offset (command → first SYN) is stored in it."""
    net.disconnect(names)
    time.sleep(0.3)
    READY_LOG.write_text("")
    syn = SynSniffer(st.target)
    t_cmd = net.connect(st.target, names)
    dpids = [int(n[1:]) for n in names]
    got = wait_ready(dpids, t_cmd, timeout)
    syns = [t for t in syn.stop() if t >= t_cmd]
    t0 = syns[0] if syns else t_cmd
    if meta is not None:
        meta["ovs_offset_ms"] = (t0 - t_cmd) * 1000
        meta["syns"] = len(syns)
    return {d: (t - t0) * 1000 for d, t in got.items()}


# ═════════════════════════════════════════════════════════════════════════════
# Packet capture on the WAN interface
# ═════════════════════════════════════════════════════════════════════════════

class WanCapture:
    """TCP payload sizes on the WAN veth (root side), split by direction."""

    def __init__(self, port: int) -> None:
        import socket
        self.port = port
        self.up: List[tuple] = []      # (t, payload) switch → controller
        self.down: List[tuple] = []
        self._s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self._s.bind((SW_IF, 0))
        self._s.settimeout(0.2)
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self) -> None:
        while not self._stop:
            try:
                pkt, _ = self._s.recvfrom(70000)
            except OSError:
                continue
            if len(pkt) < 34 or pkt[12:14] != b"\x08\x00" or pkt[23] != 6:
                continue
            ip = pkt[14:]
            ihl = (ip[0] & 0x0F) * 4
            total = struct.unpack_from("!H", ip, 2)[0]
            sport, dport = struct.unpack_from("!HH", ip, ihl)
            payload = total - ihl - (ip[ihl + 12] >> 4) * 4
            if payload <= 0:
                continue
            if dport == self.port:
                self.up.append((time.time(), payload))
            elif sport == self.port:
                self.down.append((time.time(), payload))

    def stop(self) -> "WanCapture":
        self._stop = True
        self._t.join()
        self._s.close()
        return self


# ═════════════════════════════════════════════════════════════════════════════
# Experiments
# ═════════════════════════════════════════════════════════════════════════════

def save(name: str, rows) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{name}.json").write_text(json.dumps(rows, indent=1))
    print(f"→ {RESULTS / (name + '.json')}", flush=True)


def warmup(net: Net, st: Stack, names: Optional[List[str]] = None, n: int = 2) -> None:
    for _ in range(n):
        reconnect_measure(net, st, names or net.switches[:1], timeout=30)


def exp_wire(configs, reps) -> list:
    rows = []
    net = Net(1)
    try:
        for cfg in configs:
            st = start_stack(cfg)
            try:
                warmup(net, st)
                for rep in range(reps):
                    net.disconnect()
                    time.sleep(0.3)
                    cap = WanCapture(st.wan_port)
                    time.sleep(0.2)
                    READY_LOG.write_text("")
                    t0 = net.connect(st.target)
                    wait_ready([1], t0, 30)
                    time.sleep(0.5)
                    cap.stop()
                    rows.append({"config": cfg, "rep": rep,
                                 "bytes_up": sum(n for _, n in cap.up),
                                 "bytes_down": sum(n for _, n in cap.down),
                                 "segs_up": len(cap.up), "segs_down": len(cap.down)})
                r = rows[-1]
                print(f"[wire] {cfg:16s} up={r['bytes_up']}B down={r['bytes_down']}B", flush=True)
            finally:
                st.stop()
    finally:
        net.stop()
    return rows


def exp_rtt(configs, reps, n_conn, grid) -> list:
    rows = []
    net = Net(1)
    try:
        for cfg in configs:
            st = start_stack(cfg)
            try:
                warmup(net, st)
                for rtt, loss in grid:
                    set_wan(rtt, loss)
                    for rep in range(reps):
                        times, fails, offsets = [], 0, []
                        for _ in range(n_conn):
                            m: dict = {}
                            r = reconnect_measure(net, st, ["s1"], timeout=30, meta=m)
                            offsets.append(m.get("ovs_offset_ms"))
                            if 1 in r:
                                times.append(r[1])
                            else:
                                fails += 1
                        rows.append({"config": cfg, "rtt_ms": rtt, "loss_pct": loss, "rep": rep,
                                     "ready_ms": stats(times), "failures": fails,
                                     "samples": times, "ovs_offset_ms": offsets})
                        print(f"[rtt] {cfg:16s} rtt={rtt:>3}ms loss={loss}% rep={rep} "
                              f"p50={stats(times).get('p50', float('nan')):.1f}ms "
                              f"fail={fails}", flush=True)
                set_wan(0, 0)
            finally:
                set_wan(0, 0)
                st.stop()
    finally:
        net.stop()
    return rows


# ── Instrumented OpenFlow client over the same testbed link ─────────────────
#
# Open vSwitch needs up to about 0.5 s to complete a new controller connection
# when it is otherwise idle (measured from its own TCP SYN), which hides the
# millisecond-scale differences between channel configurations. The delay and
# loss sweep and the completion time of reconnection storms therefore use a
# minimal OpenFlow 1.3 client (evaluation.channel_bench.EmuSwitch) on the same
# namespace, veth pair, netem shaping, proxies and controller as the real-OVS
# experiments; only the switch end of the channel differs.

def _target(st: Stack):
    _, host, port = st.target.split(":")
    return host, int(port)


def _emu_connect_many(st: Stack, n: int, timeout: float, concurrent: bool) -> List[Optional[float]]:
    sys.path.insert(0, str(ROOT))
    from evaluation.channel_bench import _connect_one
    host, port = _target(st)

    async def go():
        if concurrent:
            res = await asyncio.gather(*[_connect_one(port, timeout, host) for _ in range(n)])
        else:
            res = []
            for _ in range(n):
                r = await _connect_one(port, timeout, host)
                r[1].close()
                await asyncio.sleep(0.05)
                res.append(r)
        for _, sw in res:
            sw.close()
        await asyncio.sleep(0.2)
        return [t for t, _ in res]
    return asyncio.run(go())


def exp_rtt_emu(configs, reps, n_conn, grid) -> list:
    rows = []
    for cfg in configs:
        st = start_stack(cfg)
        try:
            _emu_connect_many(st, 3, 30, concurrent=False)          # warm-up
            for rtt, loss in grid:
                set_wan(rtt, loss)
                for rep in range(reps):
                    res = _emu_connect_many(st, n_conn, 30, concurrent=False)
                    times = [t for t in res if t is not None]
                    rows.append({"config": cfg, "rtt_ms": rtt, "loss_pct": loss, "rep": rep,
                                 "client": "instrumented", "ready_ms": stats(times),
                                 "failures": len(res) - len(times), "samples": times})
                    print(f"[rtt] {cfg:16s} rtt={rtt:>3}ms loss={loss}% rep={rep} "
                          f"p50={stats(times).get('p50', float('nan')):.1f}ms "
                          f"fail={len(res) - len(times)}", flush=True)
            set_wan(0, 0)
        finally:
            set_wan(0, 0)
            st.stop()
    return rows


def exp_storm_emu(configs, reps, sizes, rtt) -> list:
    rows = []
    for n in sizes:
        for cfg in configs:
            st = start_stack(cfg)
            try:
                set_wan(rtt, 0)
                _emu_connect_many(st, min(n, 20), 60, concurrent=True)   # warm-up
                for rep in range(reps):
                    c0, s0 = st.cpu("ctrl"), st.cpu("sw")
                    res = _emu_connect_many(st, n, 120, concurrent=True)
                    times = [t for t in res if t is not None]
                    rows.append({"config": cfg, "n_switches": n, "rtt_ms": rtt, "rep": rep,
                                 "client": "instrumented",
                                 "all_ready_ms": max(times) if len(times) == n else None,
                                 "ready_ms": stats(times), "failures": n - len(times),
                                 "ctrl_cpu_s": st.cpu("ctrl") - c0,
                                 "sw_cpu_s": st.cpu("sw") - s0})
                    x = rows[-1]
                    print(f"[storm-emu] {cfg:16s} n={n:>3} rep={rep} all_ready="
                          f"{x['all_ready_ms'] and round(x['all_ready_ms'], 1)}ms "
                          f"cpu={x['ctrl_cpu_s']:.2f}s fail={x['failures']}", flush=True)
            finally:
                set_wan(0, 0)
                st.stop()
    return rows


def exp_arrival_emu(configs, reps, n, rates, rtt) -> list:
    """n instrumented switches arrive as a Poisson process at `rate` per second."""
    sys.path.insert(0, str(ROOT))
    from evaluation.channel_bench import _connect_one
    rows = []
    for cfg in configs:
        st = start_stack(cfg)
        host, port = _target(st)
        try:
            set_wan(rtt, 0)
            _emu_connect_many(st, 3, 30, concurrent=False)          # warm-up
            for rate in rates:
                for rep in range(reps):
                    rng = random.Random(rep * 1000 + rate)

                    async def go():
                        tasks, nxt = [], time.perf_counter()
                        for _ in range(n):
                            tasks.append(asyncio.ensure_future(_connect_one(port, 120, host)))
                            nxt += rng.expovariate(rate)
                            await asyncio.sleep(max(0.0, nxt - time.perf_counter()))
                        res = await asyncio.gather(*tasks)
                        for _, sw in res:
                            sw.close()
                        await asyncio.sleep(0.2)
                        return [t for t, _ in res]

                    c0, w0 = st.cpu("ctrl"), time.time()
                    res = asyncio.run(go())
                    wall = time.time() - w0
                    lat = [t for t in res if t is not None]
                    rows.append({"config": cfg, "rate": rate, "n_switches": n, "rep": rep,
                                 "client": "instrumented", "rtt_ms": rtt,
                                 "ready_ms": stats(lat), "failures": n - len(lat),
                                 "ctrl_cpu_pct": 100 * (st.cpu("ctrl") - c0) / wall})
                    x = rows[-1]
                    print(f"[arrival-emu] {cfg:16s} R={rate:>3}/s rep={rep} "
                          f"p50={x['ready_ms'].get('p50', float('nan')):.1f}ms "
                          f"p95={x['ready_ms'].get('p95', float('nan')):.1f}ms "
                          f"cpu={x['ctrl_cpu_pct']:.1f}% fail={x['failures']}", flush=True)
        finally:
            set_wan(0, 0)
            st.stop()
    return rows


def exp_storm(configs, reps, sizes, rtt) -> list:
    rows = []
    for n in sizes:
        net = Net(n)
        try:
            for cfg in configs:
                st = start_stack(cfg)
                try:
                    set_wan(rtt, 0)
                    warmup(net, st, net.switches, n=1)
                    for rep in range(reps):
                        c0, s0 = st.cpu("ctrl"), st.cpu("sw")
                        m: dict = {}
                        r = reconnect_measure(net, st, net.switches, timeout=180, meta=m)
                        rows.append({"config": cfg, "n_switches": n, "rtt_ms": rtt, "rep": rep,
                                     "all_ready_ms": max(r.values()) if len(r) == n else None,
                                     "ready_ms": stats(list(r.values())),
                                     "failures": n - len(r),
                                     "ovs_offset_ms": m.get("ovs_offset_ms"),
                                     "syns": m.get("syns"),
                                     "ctrl_cpu_s": st.cpu("ctrl") - c0,
                                     "sw_cpu_s": st.cpu("sw") - s0,
                                     "ctrl_rss_mb": st.rss_mb("ctrl"),
                                     "sw_rss_mb": st.rss_mb("sw")})
                        x = rows[-1]
                        print(f"[storm] {cfg:16s} n={n:>3} rep={rep} all_ready="
                              f"{x['all_ready_ms']}ms cpu={x['ctrl_cpu_s']:.2f}s "
                              f"fail={x['failures']}", flush=True)
                finally:
                    set_wan(0, 0)
                    st.stop()
        finally:
            net.stop()
    return rows


def exp_arrival(configs, reps, n, rates, rtt) -> list:
    rows = []
    net = Net(n)
    try:
        for cfg in configs:
            st = start_stack(cfg)
            try:
                set_wan(rtt, 0)
                warmup(net, st, net.switches, n=1)
                for rate in rates:
                    for rep in range(reps):
                        net.disconnect()
                        time.sleep(0.5)
                        READY_LOG.write_text("")
                        rng = random.Random(rep * 1000 + rate)
                        c0, w0 = st.cpu("ctrl"), time.time()
                        syn = SynSniffer(st.target)
                        starts = {}
                        # Commands are issued without waiting for ovs-vsctl to return,
                        # so the Poisson schedule is not stretched by command latency.
                        pending = []
                        nxt = time.time()
                        for name in net.switches:
                            starts[int(name[1:])] = time.time()
                            pending.append(subprocess.Popen(
                                ["ovs-vsctl", "--no-wait", "set-controller", name, st.target],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                            nxt += rng.expovariate(rate)
                            time.sleep(max(0.0, nxt - time.time()))
                        for proc in pending:
                            proc.wait()
                        got = wait_ready(list(starts), min(starts.values()), 120)
                        wall = time.time() - w0
                        # Switch i's SYN is the i-th SYN (commands are issued in
                        # order, OVS's internal delay is near-constant); fall back
                        # to command times if the counts do not match.
                        syns = [t for t in syn.stop() if t >= min(starts.values())]
                        if len(syns) >= n:
                            order = sorted(starts, key=starts.get)
                            starts = {d: syns[i] for i, d in enumerate(order)}
                        lat = [(got[d] - starts[d]) * 1000 for d in starts if d in got]
                        span = max(starts.values()) - min(starts.values())
                        rows.append({"config": cfg, "rate": rate, "n_switches": n, "rep": rep,
                                     "achieved_rate": (n - 1) / span if span > 0 else None,
                                     "rtt_ms": rtt, "ready_ms": stats(lat),
                                     "failures": n - len(lat),
                                     "ctrl_cpu_pct": 100 * (st.cpu("ctrl") - c0) / wall})
                        x = rows[-1]
                        print(f"[arrival] {cfg:16s} R={rate:>3}/s rep={rep} "
                              f"p50={x['ready_ms'].get('p50', float('nan')):.1f}ms "
                              f"cpu={x['ctrl_cpu_pct']:.1f}%", flush=True)
            finally:
                set_wan(0, 0)
                st.stop()
    finally:
        net.stop()
    return rows


# ── host-side traffic tools (run inside Mininet hosts with the system python) ─

FLOOD_TX = r'''
import socket, struct, sys, time, json, random
iface, dst_mac, rate, dur, out = sys.argv[1], bytes.fromhex(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), sys.argv[5]
dscps = [46, 10, 0]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((iface, 0))
gap, t_end, seq, sent = 1.0 / rate, time.time() + dur, 0, []
nxt = time.time()
while time.time() < t_end:
    seq += 1
    src = b"\x02\x7f" + struct.pack("!I", seq)
    payload = struct.pack("!Id", seq, time.time()) + b"\0" * 32
    # Every frame is a new flow: unique source port (and source MAC).
    udp = struct.pack("!HHHH", 1024 + seq % 60000, 9999, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, dscps[seq % 3] << 2, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + udp
    s.send(dst_mac + src + b"\x08\x00" + ip)
    nxt += gap
    d = nxt - time.time()
    if d > 0: time.sleep(d)
json.dump({"sent": seq}, open(out, "w"))
'''

FLOOD_RX = r'''
import socket, struct, sys, time, json
iface, dur, out = sys.argv[1], float(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800)); s.bind((iface, 0))
s.settimeout(0.5); t_end = time.time() + dur; lat = {}
while time.time() < t_end:
    try: pkt = s.recv(2048)
    except OSError: continue
    if len(pkt) < 54 or pkt[23] != 17 or struct.unpack_from("!H", pkt, 36)[0] != 9999: continue
    seq, ts = struct.unpack_from("!Id", pkt, 42)
    lat.setdefault(seq, (time.time() - ts) * 1000)
json.dump({"latencies_ms": list(lat.values())}, open(out, "w"))
'''

TA_TX = r'''
import socket, struct, sys, time, json, random
iface, dst_mac, n, spacing, out, seed = sys.argv[1], bytes.fromhex(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), sys.argv[5], int(sys.argv[6])
CLASSES = {"arp": (42, 42), "tcp_syn": (74, 78), "dns_query": (70, 130), "http_request": (350, 700), "bulk_segment": (1400, 1514)}
rng = random.Random(seed)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((iface, 0))
log = []
for i in range(n):
    cls = rng.choice(list(CLASSES)); lo, hi = CLASSES[cls]; L = rng.randint(lo, hi)
    src = b"\x02\x5a" + struct.pack("!I", i + 1)
    etype = b"\x08\x06" if cls == "arp" else b"\x08\x00"
    s.send(dst_mac + src + etype + b"\0" * (L - 14))
    log.append((time.time(), cls))
    time.sleep(spacing)
json.dump(log, open(out, "w"))
'''


def _host_script(name: str, code: str) -> Path:
    p = WORK / name
    p.write_text(code)
    return p


def exp_flood(reps, rates, duration, aesni_modes, configs=None, quota=None) -> list:
    global SW_CPU_QUOTA
    configs = configs or ["plain", "pqtls_l5", "proposed", "proposed_aes256", "proposed_chacha"]
    SW_CPU_QUOTA = quota
    rows = []
    net = Net(1, hosts=2)
    h1, h2 = net.net.get("h1"), net.net.get("h2")
    tx, rx = _host_script("flood_tx.py", FLOOD_TX), _host_script("flood_rx.py", FLOOD_RX)
    try:
        for no_aesni in aesni_modes:
            for cfg in configs:
                if cfg == "plain" and no_aesni:
                    continue
                st = start_stack(cfg, no_aesni=no_aesni)
                try:
                    set_wan(2, 0)
                    warmup(net, st)
                    for rate in rates:
                        for rep in range(reps):
                            net.disconnect()
                            sh("ovs-ofctl -O OpenFlow13 del-flows s1")
                            READY_LOG.write_text("")
                            t0 = net.connect(st.target)
                            wait_ready([1], t0, 30)
                            h2.cmd("ping -c1 -W1 10.0.0.1 >/dev/null 2>&1")   # learn h2
                            c0 = st.cpu("ctrl")
                            rx_out, tx_out = WORK / "rx.json", WORK / "tx.json"
                            rxp = h2.popen(["python3", str(rx), "h2-eth0", str(duration + 3),
                                            str(rx_out)])
                            time.sleep(0.5)
                            h1.cmd(f"python3 {tx} h1-eth0 {h2.MAC().replace(':', '')} "
                                   f"{rate} {duration} {tx_out}")
                            rxp.wait()
                            lat = json.loads(rx_out.read_text())["latencies_ms"]
                            sent = json.loads(tx_out.read_text())["sent"]
                            rows.append({"config": cfg, "no_aesni": no_aesni, "rate": rate,
                                         "sw_cpu_quota_pct": quota,
                                         "rep": rep, "sent": sent, "delivered": len(lat),
                                         "delivered_per_s": len(lat) / duration,
                                         "latency_ms": stats(lat),
                                         "ctrl_cpu_pct": 100 * (st.cpu("ctrl") - c0) / duration,
                                         "sw_cpu_s": st.cpu("sw")})
                            x = rows[-1]
                            print(f"[flood] {cfg:16s} aesni={'off' if no_aesni else 'on '} "
                                  f"R={rate:>4} rep={rep} delivered={x['delivered']}/{sent} "
                                  f"p50={x['latency_ms'].get('p50', float('nan')):.2f}ms "
                                  f"p99={x['latency_ms'].get('p99', float('nan')):.2f}ms",
                                  flush=True)
                finally:
                    set_wan(0, 0)
                    st.stop()
    finally:
        net.stop()
        SW_CPU_QUOTA = None
    return rows


def _bayes(labels: list, sizes: list, folds: int = 5) -> dict:
    idx = list(range(len(labels)))
    random.Random(1).shuffle(idx)
    correct = 0
    for f in range(folds):
        test = set(idx[f::folds])
        table, overall = defaultdict(Counter), Counter()
        for i in idx:
            if i not in test:
                table[sizes[i]][labels[i]] += 1
                overall[labels[i]] += 1
        fb = overall.most_common(1)[0][0]
        for i in test:
            pred = table[sizes[i]].most_common(1)[0][0] if sizes[i] in table else fb
            correct += pred == labels[i]
    n = len(labels)
    pl = Counter(labels)
    h = -sum(c / n * math.log2(c / n) for c in pl.values())
    ps, joint = Counter(sizes), Counter(zip(sizes, labels))
    hc = -sum(c / n * math.log2(c / ps[s]) for (s, _), c in joint.items())
    return {"accuracy": correct / n, "majority_baseline": pl.most_common(1)[0][1] / n,
            "mutual_info_bits": h - hc, "label_entropy_bits": h,
            "distinct_sizes": len(ps), "n": n, "mean_wire_bytes": sum(sizes) / n}


def exp_ta(configs, n_msgs, spacing) -> list:
    rows = []
    net = Net(1, hosts=2)
    h1, h2 = net.net.get("h1"), net.net.get("h2")
    tx = _host_script("ta_tx.py", TA_TX)
    try:
        for cfg in configs:
            st = start_stack(cfg)
            try:
                warmup(net, st)
                net.disconnect()
                sh("ovs-ofctl -O OpenFlow13 del-flows s1")
                READY_LOG.write_text("")
                t0 = net.connect(st.target)
                wait_ready([1], t0, 30)
                time.sleep(1.0)
                cap = WanCapture(st.wan_port)
                out = WORK / "ta_tx.json"
                h1.cmd(f"python3 {tx} h1-eth0 {h2.MAC().replace(':', '')} {n_msgs} "
                       f"{spacing} {out} 7")
                time.sleep(0.5)
                cap.stop()
                sent = json.loads(out.read_text())
                # Each burst (segments closer than spacing/2) is attributed to
                # the most recent send within spacing/2 before it.
                bursts, cur, last = [], None, None
                for t, n in cap.up:
                    if last is None or t - last > spacing / 2:
                        if cur:
                            bursts.append(cur)
                        cur = [t, 0]
                    cur[1] += n
                    last = t
                if cur:
                    bursts.append(cur)
                labels, sizes, j = [], [], 0
                for bt, size in bursts:
                    while j + 1 < len(sent) and sent[j + 1][0] <= bt:
                        j += 1
                    if 0 <= bt - sent[j][0] <= spacing / 2:
                        labels.append(sent[j][1])
                        sizes.append(size)
                res = _bayes(labels, sizes)
                res.update({"config": cfg, "sent": len(sent), "matched": len(labels)})
                rows.append(res)
                print(f"[ta] {cfg:16s} acc={res['accuracy']:.3f} "
                      f"(majority {res['majority_baseline']:.3f}) "
                      f"MI={res['mutual_info_bits']:.2f}/{res['label_entropy_bits']:.2f} bits "
                      f"sizes={res['distinct_sizes']} wire={res['mean_wire_bytes']:.0f}B "
                      f"matched={len(labels)}/{len(sent)}", flush=True)
            finally:
                st.stop()
    finally:
        net.stop()
    return rows


# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    if os.geteuid() != 0:
        sys.exit("run as root (sudo -E)")
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", default="wire,rtt,storm,arrival,flood,ta",
                    help="also available: flood_constrained (CPU-limited switch-side proxy)")
    ap.add_argument("--configs", default=",".join(CHANNEL_CONFIGS))
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--pilot", action="store_true", help="1-2 reps, reduced grids")
    args = ap.parse_args()
    exps = args.exp.split(",")
    configs = args.configs.split(",")
    pilot = args.pilot
    reps = 2 if pilot else args.reps

    WORK.mkdir(parents=True, exist_ok=True)
    provision_identities()
    sh("mn -c", check=False)
    wan_setup()
    meta = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "pilot": pilot, "reps": reps,
            "configs": configs, "exps": exps}
    def guarded(name: str, fn) -> None:
        """Run one experiment; a failure is logged and the next one still runs."""
        try:
            fn()
        except Exception:
            import traceback
            print(f"!!! experiment {name} failed", flush=True)
            traceback.print_exc()
            meta.setdefault("failed", []).append(name)
            set_wan(0, 0)

    try:
        if "wire" in exps:
            guarded("wire", lambda: save("wire", exp_wire(configs, 3 if pilot else reps)))
        if "rtt" in exps:
            grid = ([(0, 0), (10, 0), (50, 0), (50, 1)] if pilot else
                    [(0, 0), (2, 0), (10, 0), (50, 0), (100, 0),
                     (10, 1), (10, 2), (50, 1), (50, 2)])
            guarded("rtt", lambda: save("rtt_loss", exp_rtt_emu(configs, reps, 5 if pilot else 20, grid)))
        if "storm" in exps:
            sizes = [20, 80] if pilot else [20, 45, 80, 125]
            guarded("storm", lambda: save("storm", exp_storm(configs, reps, sizes, 2)))
            guarded("storm_emu", lambda: save("storm_emu", exp_storm_emu(configs, reps, sizes, 2)))
        if "arrival" in exps:
            guarded("arrival", lambda: save("arrival", exp_arrival(
                configs, 1 if pilot else reps, 60, [30, 90] if pilot else [30, 60, 90], 2)))
            guarded("arrival_emu", lambda: save("arrival_emu", exp_arrival_emu(
                configs, 1 if pilot else reps, 60, [10, 90] if pilot else [10, 30, 60, 90], 2)))
        if "flood" in exps:
            guarded("flood", lambda: save("flood", exp_flood(
                1 if pilot else reps, [300, 1000] if pilot else [300, 1000, 2000],
                5 if pilot else 10, [False, True])))
        if "flood_constrained" in exps:
            # DSCP-driven vs fixed ciphers when the switch-side proxy runs on a
            # constrained device: CPU quota on that process, no AES-NI.
            def _constrained():
                rows = []
                for quota in ([25] if pilot else [25, 10]):
                    rows += exp_flood(1 if pilot else reps, [100, 600] if pilot else [100, 300, 600],
                                      5 if pilot else 10, [True],
                                      configs=["proposed", "proposed_aes256", "proposed_chacha",
                                               "pqtls_l5"], quota=quota)
                save("flood_constrained", rows)
            guarded("flood_constrained", _constrained)
        if "ta" in exps:
            ta_cfgs = ["plain", "tls_classical", "pqtls_l5", "proposed",
                       "proposed_pad1024", "proposed_pad2048"]
            guarded("ta", lambda: save("traffic_analysis", exp_ta(ta_cfgs, 300 if pilot else 1500, 0.02)))
    finally:
        meta["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
        RESULTS.mkdir(parents=True, exist_ok=True)
        # Runs with a non-default experiment list keep their own metadata, so
        # a follow-up run never overwrites the record of the main run.
        default = ap.get_default("exp").split(",")
        meta_name = "meta.json" if exps == default else f"meta_{'_'.join(exps)}.json"
        (RESULTS / meta_name).write_text(json.dumps(meta, indent=1))
        set_wan(0, 0)
        wan_teardown()
        sh("mn -c", check=False)


if __name__ == "__main__":
    main()
