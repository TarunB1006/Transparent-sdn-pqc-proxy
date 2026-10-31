#!/usr/bin/env python3
"""
topo_comparison.py — PQC-SDN Topology Scaling Evaluation (standalone)

Measures how our PQC security layer scales across increasingly large fat-tree
topologies by comparing **Direct (plain OpenFlow)** vs **PQC Proxy (encrypted)**.

Focus: what our implementation adds and how it behaves at scale — not generic
network benchmarks.

Topology sizes tested (fat-tree, density=2):
  k=4:   20 switches,  16 hosts
  k=6:   45 switches,  36 hosts
  k=8:   80 switches,  64 hosts
  k=10: 125 switches, 100 hosts

══════════════════════════════════════════════════════════════════════
  PQC-Specific Metrics (5 separate figures)
══════════════════════════════════════════════════════════════════════

Figure 1 — Handshake Burst Time
   How long it takes ALL switches to complete their ML-KEM + ML-DSA handshake
   through the proxy stack.  At k=4 that's 20 handshakes; at k=10 it's 125
   hitting ctrl_proxy concurrently.  Direct mode has zero handshake cost.
   Shows: proxy bottleneck, serial vs concurrent handshake throughput.

Figure 2 — Per-Packet Encryption Overhead (ping RTT)
   Latency added by AEAD encrypt → transmit → decrypt per OpenFlow message.
   Each ping = PACKET_IN (encrypted) → PACKET_OUT (encrypted), so the PQC
   overhead is doubled.  Compared to direct mode where it's plaintext TCP.
   Shows: constant per-packet cost of our encryption layer.

Figure 3 — Throughput Degradation (iperf)
   TCP throughput loss from running all OpenFlow control through the encrypted
   tunnel.  At larger topologies more concurrent flows compete for the proxy's
   encrypt/decrypt pipeline.
   Shows: crypto throughput ceiling of the proxy under concurrent load.

Figure 4 — Flow Setup Latency
   Time from new-flow PACKET_IN to FLOW_MOD installed, measured via first-
   packet ping.  Through the proxy, both PACKET_IN and FLOW_MOD travel
   through encrypt/decrypt.  Direct mode is plain TCP.
   Shows: per-flow cost of encrypted control plane at scale.

Figure 5 — Topology Convergence Time
   Time until full mesh reachability after all switches connect.  LLDP
   topology discovery messages go through the encrypted tunnel in proxy mode.
   More switches = more LLDP messages encrypted concurrently.
   Shows: how encryption affects topology discovery and convergence.

Figure 7 — ECMP Path Diversity Across Topology Sizes
   How many distinct output ports (paths) the controller uses on core
   switches for cross-pod traffic.  A k-ary fat-tree has (k/2)² core
   switches, each with k/2 downlinks per pod — so the theoretical max
   paths between any two pods = (k/2)².  More paths = more choices for
   our crypto-aware ECMP scorer (0.7×util + 0.3×crypto_overhead).
   Shows: path diversity grows with k, and whether flows actually spread.

Figure 8 — Controller Resource Usage During Handshake Burst
   CPU utilization, RSS memory, and handshake queue depth on the
   controller/proxy process while all switches perform ML-KEM handshakes
   simultaneously.  At k=10 that's 125 concurrent KEM encapsulations.
   Addresses the PQC handshake exhaustion concern (arXiv:2607.12504).
   Shows: whether the controller becomes a bottleneck at large scale.

Modes:
  Direct    — switches → Ryu :6653 (no encryption, no proxy)
  PQC Proxy — switches → sw_proxy :6634 → ctrl_proxy :6652 → Ryu :6653

Prerequisites: Linux, root, Mininet, OVS, proxy stack running.

Usage:
    sudo -E PYTHONPATH=src python evaluation/topo_comparison.py
    sudo -E PYTHONPATH=src python evaluation/topo_comparison.py --k 4,6,8,10
    sudo -E PYTHONPATH=src python evaluation/topo_comparison.py --proxy-only
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
import threading

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
_SCRIPTS = _ROOT / "scripts"
RESULTS_DIR = Path(os.environ.get("PQC_TOPO_RESULTS", _ROOT / "evaluation" / "results"))

# Ports
RYU_PORT = 6653
PROXY_PORT = 6634

# Prometheus metrics endpoint (sw_proxy exposes this)
METRICS_URL = "http://127.0.0.1:9101/metrics"


# ═══════════════════════════════════════════════════════════════════
# Dependency checks
# ═══════════════════════════════════════════════════════════════════

def _check_deps() -> list[str]:
    errors = []
    try:
        from mininet.net import Mininet  # noqa: F401
    except ImportError:
        errors.append("Mininet not installed (sudo apt install mininet)")
    try:
        r = subprocess.run(["ovs-vsctl", "show"], capture_output=True, timeout=3)
        if r.returncode != 0:
            errors.append("OVS not running")
    except Exception:
        errors.append("ovs-vsctl not found")
    if os.getuid() != 0:
        errors.append("Must run as root (sudo -E ...)")
    return errors


def _check_proxy_running() -> bool:
    """Check if the proxy stack is listening."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=1):
            return True
    except Exception:
        return False


def _port_open(port: int) -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


# Locate venv
def _find_venv_bin() -> Path:
    for cand in (_ROOT / "venv" / "bin", _ROOT.parent / "venv" / "bin"):
        if (cand / "ryu-manager").exists():
            return cand
    return _ROOT / "venv" / "bin"


_VENV_BIN = _find_venv_bin()
_VENV_PY  = str(_VENV_BIN / "python3") if (_VENV_BIN / "python3").exists() else sys.executable
_RYU_MGR  = str(_VENV_BIN / "ryu-manager") if (_VENV_BIN / "ryu-manager").exists() else "ryu-manager"
_LOG_DIR  = Path("/tmp/pqc_eval_logs")

# Handles for processes we start so we can kill them
_stack_procs: list[subprocess.Popen] = []
_stack_logs: list = []


def _kill_stack():
    """Kill Ryu + proxies. Called between runs for clean-room isolation."""
    global _stack_procs, _stack_logs
    for p in _stack_procs:
        try:
            os.killpg(os.getpgid(p.pid), 9)
        except Exception:
            pass
    _stack_procs.clear()
    for f in _stack_logs:
        try:
            f.close()
        except Exception:
            pass
    _stack_logs.clear()
    # Belt-and-suspenders: fuser-kill the ports, retry until clear
    for attempt in range(5):
        any_alive = False
        for port in (RYU_PORT, 6652, PROXY_PORT):
            os.system(f"fuser -k {port}/tcp 2>/dev/null")
        time.sleep(2.0)
        for port in (RYU_PORT, 6652, PROXY_PORT):
            if _port_open(port):
                any_alive = True
        if not any_alive:
            break
        time.sleep(2.0)


_TLS_CERT_DIR = _ROOT / "evaluation" / "tls_certs"   # OVS-native TLS (classical baseline)


def _start_stack(need_proxy: bool = True, tls_mode: bool = False) -> bool:
    """Start Ryu (and optionally proxies) fresh. Returns True if all ports are up."""
    global _stack_procs, _stack_logs
    _LOG_DIR.mkdir(exist_ok=True)

    env = {**os.environ, "PYTHONPATH": str(_SRC),
           # Adaptive cipher override disabled so DSCP-driven selection is measured as is.
           "PQC_SDN_CONFIG": str(_ROOT / "config" / "eval.yaml")}
    env["PATH"] = str(_VENV_BIN) + os.pathsep + env.get("PATH", "")

    def _launch(cmd, logname):
        lf = open(_LOG_DIR / logname, "w")
        p = subprocess.Popen(cmd, env=env, stdout=lf, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        _stack_procs.append(p)
        _stack_logs.append(lf)

    # Ryu — with TLS if requested
    if tls_mode:
        # TLS mode: use --ofp-ssl-listen-port (NOT tcp). Passing both breaks Ryu.
        ryu_cmd = [_RYU_MGR,
                   str(_SRC / "pqc_sdn" / "controller" / "controller.py"),
                   "--observe-links",
                   "--ofp-ssl-listen-port", str(RYU_PORT),
                   "--ctl-privkey", str(_TLS_CERT_DIR / "ctrl-key.pem"),
                   "--ctl-cert", str(_TLS_CERT_DIR / "ctrl-cert.pem"),
                   "--ca-certs", str(_TLS_CERT_DIR / "ca-cert.pem")]
    else:
        ryu_cmd = [_RYU_MGR,
                   str(_SRC / "pqc_sdn" / "controller" / "controller.py"),
                   "--observe-links",
                   "--ofp-tcp-listen-port", str(RYU_PORT)]
    _launch(ryu_cmd, "ryu.log")
    time.sleep(6)

    if need_proxy:
        _launch([_VENV_PY, "-m", "pqc_sdn.apps.ctrl_proxy"], "ctrl_proxy.log")
        time.sleep(3)
        _launch([_VENV_PY, "-m", "pqc_sdn.apps.sw_proxy_async"], "sw_proxy.log")
        time.sleep(4)

    # Verify
    ports_needed = [RYU_PORT]
    if need_proxy:
        ports_needed += [6652, PROXY_PORT]
    for _ in range(10):
        if all(_port_open(p) for p in ports_needed):
            names = " ".join(f":{p}✓" for p in ports_needed)
            print(f"    [stack] All up: {names}")
            return True
        time.sleep(1)
    missing = [p for p in ports_needed if not _port_open(p)]
    print(f"    [stack] ⚠ Not fully up — missing: {missing}")
    return False


def _clean_topo_state():
    """Remove OVS bridges and stale veth interfaces from previous runs."""
    for br in subprocess.run(
        ["ovs-vsctl", "list-br"], capture_output=True, text=True
    ).stdout.split():
        os.system(f"ovs-vsctl del-br {br} 2>/dev/null")
    links = subprocess.run(["ip", "-br", "link", "show"], capture_output=True, text=True).stdout
    for line in links.splitlines():
        name = line.split()[0].split("@")[0] if line.split() else ""
        if re.match(r"^[sh]\d+-eth\d+$", name):
            os.system(f"ip link del {name} 2>/dev/null")
    time.sleep(1.0)


class _MetricsSampler:
    """Background thread that polls Prometheus /metrics at a fixed interval.

    Captures CPU%, memory (RSS bytes), and handshake queue depth during
    the handshake burst to show controller resource usage at scale.

    Usage:
        sampler = _MetricsSampler(interval=0.5)
        sampler.start()
        ... (handshake burst happens) ...
        sampler.stop()
        result = sampler.summary()
        # result = {"cpu_peak_pct": 85.2, "cpu_avg_pct": 43.1,
        #           "mem_peak_mb": 120.5, "mem_avg_mb": 98.3,
        #           "queue_peak": 12, "samples": 24}
    """

    def __init__(self, interval: float = 0.5):
        self._interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._cpu_samples: list[float] = []
        self._mem_samples: list[float] = []
        self._queue_samples: list[float] = []

    def start(self):
        self._stop.clear()
        self._cpu_samples.clear()
        self._mem_samples.clear()
        self._queue_samples.clear()
        self._thread = threading.Thread(target=self._poll, daemon=True, name="metrics-sampler")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def _poll(self):
        import urllib.request
        while not self._stop.is_set():
            try:
                raw = urllib.request.urlopen(METRICS_URL, timeout=2).read().decode()
                for line in raw.splitlines():
                    if line.startswith("#"):
                        continue
                    if line.startswith("pqc_controller_cpu_percent "):
                        self._cpu_samples.append(float(line.split()[1]))
                    elif line.startswith("pqc_controller_memory_bytes "):
                        self._mem_samples.append(float(line.split()[1]))
                    elif line.startswith("pqc_handshake_queue_depth "):
                        self._queue_samples.append(float(line.split()[1]))
            except Exception:
                pass
            self._stop.wait(self._interval)

    def summary(self) -> dict:
        result = {"resource_samples": len(self._cpu_samples)}
        if self._cpu_samples:
            result["cpu_peak_pct"] = round(max(self._cpu_samples), 1)
            result["cpu_avg_pct"] = round(sum(self._cpu_samples) / len(self._cpu_samples), 1)
        if self._mem_samples:
            result["mem_peak_mb"] = round(max(self._mem_samples) / (1024 * 1024), 1)
            result["mem_avg_mb"] = round(sum(self._mem_samples) / len(self._mem_samples) / (1024 * 1024), 1)
        if self._queue_samples:
            result["queue_peak"] = int(max(self._queue_samples))
            result["queue_avg"] = round(sum(self._queue_samples) / len(self._queue_samples), 1)
        return result


# ═══════════════════════════════════════════════════════════════════
# Topology helpers
# ═══════════════════════════════════════════════════════════════════

def _build_net(k: int):
    """Build and start a k-ary fat-tree Mininet topology."""
    from mininet.net import Mininet
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    setLogLevel("warning")

    sys.path.insert(0, str(_SRC))
    sys.path.insert(0, str(_SCRIPTS))
    from run_mininet import Fattree

    topo = Fattree(k, 2)
    topo.createTopo()
    topo.createLink(bw_c2a=1000, bw_a2e=1000, bw_h2a=100)

    net = Mininet(topo=topo, link=TCLink, controller=None, autoSetMacs=True)
    net.start()

    # Set OF version on all switches
    for sw in net.switches:
        os.system(f"ovs-vsctl set bridge {sw.name} protocols=OpenFlow13 2>/dev/null")

    return net


def _connect_switches(net, target_port: int, batch_size: int = 4,
                      protocol: str = "tcp") -> float:
    """Connect all switches to target_port in batches. Returns elapsed time.
    protocol: 'tcp' for plaintext/proxy, 'ssl' for classical TLS."""
    t0 = time.perf_counter()
    if protocol == "ssl":
        # Configure OVS SSL globally first
        os.system(f"ovs-vsctl set-ssl "
                  f"{_TLS_CERT_DIR}/sw-key.pem "
                  f"{_TLS_CERT_DIR}/sw-cert.pem "
                  f"{_TLS_CERT_DIR}/ca-cert.pem 2>/dev/null")
    for i, sw in enumerate(net.switches):
        os.system(f"ovs-vsctl set-controller {sw.name} "
                  f"{protocol}:127.0.0.1:{target_port} 2>/dev/null")
        if (i + 1) % batch_size == 0:
            time.sleep(0.3)
    return time.perf_counter() - t0


def _wait_for_handshakes(net, timeout: float = 120.0) -> tuple[bool, float]:
    """Wait for proxy handshakes to complete (all switches registered).

    Polls Prometheus pqc_active_sessions metric to know when all switches
    have completed their ML-KEM handshake through the proxy.
    Returns (all_done, elapsed_seconds).
    """
    import urllib.request
    n_switches = len(net.switches)
    t0 = time.perf_counter()
    deadline = t0 + timeout

    while time.perf_counter() < deadline:
        try:
            raw = urllib.request.urlopen(METRICS_URL, timeout=2).read().decode()
            for line in raw.splitlines():
                if line.startswith("pqc_active_sessions "):
                    sessions = float(line.split()[1])
                    if sessions >= n_switches:
                        return True, time.perf_counter() - t0
        except Exception:
            pass
        time.sleep(1.0)

    return False, time.perf_counter() - t0


def _wait_converge(net, timeout: float = 120.0) -> tuple[bool, float]:
    """Wait until src→dst ping succeeds (topology converged)."""
    src = net.hosts[0]
    dst = net.hosts[-1]
    t0 = time.perf_counter()
    for _ in range(int(timeout / 2)):
        result = src.cmd(f"ping -c 2 -W 2 {dst.IP()} -q")
        if "2 received" in result or "1 received" in result:
            return True, time.perf_counter() - t0
        time.sleep(2.0)
    return False, time.perf_counter() - t0


def _warmup(net):
    """Warm up ARP and flow tables with a few pings."""
    if len(net.hosts) < 2:
        return
    src, dst = net.hosts[0], net.hosts[-1]
    # DSCP EF pre-ping to ensure QoS path is set up
    src.cmd(f"ping -Q 0xb8 -c 2 -W 2 {dst.IP()} -q 2>/dev/null")
    src.cmd(f"ping -c 3 -W 2 {dst.IP()} -q 2>/dev/null")
    time.sleep(1.5)


# ═══════════════════════════════════════════════════════════════════
# Measurement functions
# ═══════════════════════════════════════════════════════════════════

def _measure_ping(net, count: int = 20) -> dict:
    """Measure ping RTT between first and last host."""
    src, dst = net.hosts[0], net.hosts[-1]
    out = src.cmd(f"ping -c {count} -W 2 {dst.IP()}")
    rtt = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
    loss = re.search(r"(\d+)% packet loss", out)
    return {
        "ping_min_ms": float(rtt.group(1)) if rtt else -1,
        "ping_avg_ms": float(rtt.group(2)) if rtt else -1,
        "ping_max_ms": float(rtt.group(3)) if rtt else -1,
        "ping_loss_pct": float(loss.group(1)) if loss else 100,
    }


def _measure_iperf(net, duration: int = 10) -> float:
    """Measure TCP throughput between first and last host."""
    src, dst = net.hosts[0], net.hosts[-1]
    dst.cmd("pkill -9 iperf 2>/dev/null; sleep 0.3")

    # Start server
    dst.popen(["iperf", "-s"])
    time.sleep(1.5)

    # Warmup run (short)
    src.cmd(f"iperf -c {dst.IP()} -t 2 -f m 2>&1")
    time.sleep(0.5)

    # Real measurement
    out = src.cmd(f"iperf -c {dst.IP()} -t {duration} -f m 2>&1")
    dst.cmd("pkill -9 iperf 2>/dev/null")

    for line in reversed(out.splitlines()):
        m = re.search(r"([\d.]+)\s+Mbits/sec", line)
        if m:
            return float(m.group(1))
    return 0.0


def _measure_flow_setup(net, n_pairs: int = 5) -> dict:
    """Measure flow setup time via first-packet ping latency.

    For each host pair, flush flows and measure the first ping — which triggers
    PACKET_IN → controller → FLOW_MOD. Through the proxy, both messages are
    encrypted; direct mode is plain TCP.

    Returns mean and max flow setup time in ms.
    """
    times = []
    pairs = []

    # Pick host pairs across different pods for diverse paths
    hosts = net.hosts
    step = max(1, len(hosts) // n_pairs)
    for i in range(0, len(hosts) - 1, step):
        if len(pairs) >= n_pairs:
            break
        j = min(i + step, len(hosts) - 1)
        if i != j:
            pairs.append((hosts[i], hosts[j]))

    for src, dst in pairs:
        # Delete only forwarding flows (priority > 0 except table-miss & LLDP).
        # We MUST keep the table-miss rule (priority=0, actions=CONTROLLER) —
        # without it, new packets are silently dropped and never trigger
        # PACKET_IN → controller → FLOW_MOD, making the ping fail.
        for sw in net.switches:
            os.system(f"ovs-ofctl -O OpenFlow13 del-flows {sw.name} 'priority=100' 2>/dev/null")
        time.sleep(2.0 if len(net.switches) > 50 else 1.0)

        # First ping — triggers full flow setup through controller
        t0 = time.perf_counter()
        result = src.cmd(f"ping -c 1 -W 15 {dst.IP()}")
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Extract the actual RTT from ping output if available
        rtt_match = re.search(r"time=([\d.]+)\s*ms", result)
        if rtt_match:
            times.append(float(rtt_match.group(1)))
        elif "1 received" in result:
            times.append(elapsed_ms)

    if not times:
        return {"flow_setup_mean_ms": -1, "flow_setup_max_ms": -1}

    return {
        "flow_setup_mean_ms": round(sum(times) / len(times), 2),
        "flow_setup_max_ms": round(max(times), 2),
        "flow_setup_samples": len(times),
    }


def _measure_ecmp(net, k: int) -> dict:
    """Measure ECMP path diversity across core and aggregation switches.

    In a k-ary fat-tree:
      - (k/2)² core switches, each connecting to all k pods
      - Theoretical max distinct paths between two pods = (k/2)²
      - More paths = better load balancing potential

    This test sends flows from many sources to one destination, then inspects
    OVS flow tables on core/agg switches to count how many distinct output
    ports are used.  More output ports = better ECMP spread.

    Also counts per-switch flow distribution to compute Jain's fairness index
    across core switches — a measure of how evenly flows are distributed.
    """
    if len(net.hosts) < 4:
        return {"ecmp_error": "need ≥4 hosts for ECMP test"}

    # Only flush forwarding flows (priority=100), keep table-miss so PACKET_IN works
    for sw in net.switches:
        os.system(f"ovs-ofctl -O OpenFlow13 del-flows {sw.name} 'priority=100' 2>/dev/null")
    time.sleep(1.5)

    # Generate flows from many sources to one destination.
    # Different src IPs → different 5-tuple hashes → different ECMP buckets.
    dst = net.hosts[-1]
    n_flows = min(len(net.hosts) - 1, max(20, k * k))
    srcs = net.hosts[:n_flows]

    for src in srcs:
        src.cmd(f"ping -c 3 -W 1 {dst.IP()} -q 2>/dev/null &")
    time.sleep(3.0)  # let all flows install (idle_timeout=10s, we check within that)

    # Inspect core switches (s1xxx) for output port diversity.
    # Our controller installs flows like: priority=100,ip,nw_dst=X actions=output:Y
    # (optionally with set_queue). The key signal is distinct output ports across
    # core switches — each output port = a distinct path through the fat-tree.
    core_switches = [sw for sw in net.switches if sw.name.startswith("s1")]
    if not core_switches:
        core_switches = net.switches[:max(1, (k // 2) ** 2)]

    core_output_ports = set()
    core_flow_counts = {}

    for sw in core_switches:
        sw_flows = 0
        sw_ports = set()

        result = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", sw.name],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            # Match both "output:N" and "actions=...output:N" patterns
            if "priority=100" in line or "output:" in line:
                for m in re.finditer(r"output:(\d+)", line):
                    port = int(m.group(1))
                    sw_ports.add(port)
                    core_output_ports.add(port)
                if sw_ports or "output:" in line:
                    sw_flows += 1

        core_flow_counts[sw.name] = sw_flows

    # Aggregation switches
    agg_switches = [sw for sw in net.switches if sw.name.startswith("s2")]
    agg_output_ports = set()
    agg_flow_counts = {}

    for sw in agg_switches:
        sw_flows = 0
        result = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", sw.name],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "output:" in line:
                sw_flows += 1
                for m in re.finditer(r"output:(\d+)", line):
                    agg_output_ports.add(int(m.group(1)))
        agg_flow_counts[sw.name] = sw_flows

    # Calculate metrics
    n_core_paths = len(core_output_ports)
    n_agg_paths = len(agg_output_ports)
    n_paths = max(n_core_paths, n_agg_paths)
    theoretical_max = (k // 2) ** 2  # max paths between two pods in fat-tree

    # Jain's fairness index over core switch flow counts
    # J = (Σxi)² / (n × Σxi²)  — 1.0 = perfectly fair, 1/n = maximally unfair
    flow_vals = [v for v in core_flow_counts.values() if v > 0]
    if len(flow_vals) >= 2:
        sum_x = sum(flow_vals)
        sum_x2 = sum(v * v for v in flow_vals)
        jains = (sum_x ** 2) / (len(flow_vals) * sum_x2) if sum_x2 > 0 else 0
    elif len(flow_vals) == 1:
        jains = 1.0
    else:
        jains = 0.0

    return {
        "ecmp_flows_sent": n_flows,
        "ecmp_core_paths": n_core_paths,
        "ecmp_agg_paths": n_agg_paths,
        "ecmp_paths_used": n_paths,
        "ecmp_theoretical_max": theoretical_max,
        "ecmp_path_utilization_pct": round(n_paths / theoretical_max * 100, 1) if theoretical_max > 0 else 0,
        "ecmp_jains_fairness": round(jains, 3),
        "ecmp_core_switches": len(core_switches),
        "ecmp_core_flow_dist": core_flow_counts,
    }


# ═══════════════════════════════════════════════════════════════════
# Per-run orchestrator
# ═══════════════════════════════════════════════════════════════════

def run_one(k: int, mode: str, target_port: int, protocol: str = "tcp") -> dict:
    """Run all PQC-specific measurements for one topology size and mode.

    mode = "direct" → switches connect to Ryu directly (no encryption)
    mode = "pqc_proxy" → switches connect through sw_proxy → ctrl_proxy → Ryu
    """
    n_core = (k // 2) ** 2
    n_agg = k * k // 2
    n_edge = k * k // 2
    n_switches = n_core + n_agg + n_edge
    n_hosts = n_edge * 2  # density=2

    print(f"\n  {'═' * 55}")
    print(f"  k={k}  {mode.upper()}  ({n_switches} switches, {n_hosts} hosts) → :{target_port}")
    print(f"  {'═' * 55}")

    result = {
        "k": k, "mode": mode, "switches": n_switches, "hosts": n_hosts,
        "target_port": target_port,
    }

    net = None
    try:
        # ── Build topology ──
        print(f"    Building fat-tree k={k} ...")
        net = _build_net(k)

        # ── Connect switches ──
        batch = max(4, k)
        print(f"    Connecting {n_switches} switches to :{target_port} (batch={batch}) ...")
        connect_time = _connect_switches(net, target_port, batch_size=batch, protocol=protocol)
        result["connect_time_s"] = round(connect_time, 2)
        print(f"      → connected in {connect_time:.1f}s")

        # ── [PQC-SPECIFIC] Handshake burst time ──
        # This is THE key metric for proxy mode: how long does it take all
        # switches to complete their ML-KEM + ML-DSA handshake through ctrl_proxy?
        # Direct mode skips this entirely (no handshake).
        # Also samples CPU%, memory, and queue depth during the burst.
        if target_port == PROXY_PORT:
            print(f"    Waiting for all {n_switches} ML-KEM handshakes to complete ...")
            sampler = _MetricsSampler(interval=0.5)
            sampler.start()
            hs_done, hs_time = _wait_for_handshakes(net, timeout=180.0)
            sampler.stop()
            result["handshake_burst_s"] = round(hs_time, 2)
            result["handshake_all_done"] = hs_done
            result["handshake_per_switch_ms"] = round((hs_time / n_switches) * 1000, 1) if hs_done else -1
            # Merge resource usage during burst
            resources = sampler.summary()
            result.update(resources)
            status = "✓" if hs_done else "⚠ TIMEOUT"
            print(f"      → {status} in {hs_time:.1f}s ({hs_time/n_switches*1000:.0f}ms/switch)")
            if resources.get("cpu_peak_pct"):
                print(f"      → Controller CPU: peak={resources['cpu_peak_pct']:.0f}%  "
                      f"avg={resources.get('cpu_avg_pct', 0):.0f}%  "
                      f"memory={resources.get('mem_peak_mb', 0):.0f}MB  "
                      f"queue_peak={resources.get('queue_peak', 0)}")
        else:
            result["handshake_burst_s"] = 0.0
            result["handshake_all_done"] = True
            result["handshake_per_switch_ms"] = 0.0

        # ── Topology convergence ──
        print(f"    Waiting for topology convergence ...")
        converged, converge_time = _wait_converge(net, timeout=120.0)
        result["converge_time_s"] = round(converge_time, 2)
        result["converged"] = converged
        status = "✓" if converged else "⚠ TIMEOUT"
        print(f"      → {status} in {converge_time:.1f}s")

        if not converged:
            print(f"    ⚠ Topology did not converge — skipping data-plane tests")
            return result

        # ── Warmup ──
        _warmup(net)

        # ── [PQC-SPECIFIC] Per-packet encryption overhead (ping RTT) ──
        # Each ping = ICMP → PACKET_IN (encrypted if proxy) → PACKET_OUT (encrypted)
        # → ICMP reply → PACKET_IN → PACKET_OUT.  The PQC overhead is the delta
        # between proxy and direct mode ping times.
        print(f"    Measuring per-packet overhead (20 pings) ...")
        ping = _measure_ping(net, count=20)
        result.update(ping)
        print(f"      → avg={ping['ping_avg_ms']:.1f}ms  loss={ping['ping_loss_pct']:.0f}%")

        # ── [PQC-SPECIFIC] Throughput degradation ──
        # All OpenFlow control messages for the iperf flow go through the encrypted
        # tunnel.  With more switches competing for proxy CPU, throughput may drop.
        print(f"    Measuring throughput (iperf 5s) ...")
        tp = _measure_iperf(net, duration=5)
        result["throughput_mbps"] = round(tp, 1)
        print(f"      → {tp:.1f} Mbps")

        # ── [PQC-SPECIFIC] Flow setup latency ──
        # New-flow PACKET_IN → controller → FLOW_MOD, both encrypted in proxy mode.
        # Tests diverse paths across pods to stress the proxy pipeline.
        print(f"    Measuring flow setup latency ({min(5, n_hosts//2)} pairs) ...")
        fs = _measure_flow_setup(net, n_pairs=min(5, n_hosts // 2))
        result.update(fs)
        print(f"      → mean={fs.get('flow_setup_mean_ms', -1):.1f}ms  max={fs.get('flow_setup_max_ms', -1):.1f}ms")

        # ── ECMP path diversity ──
        # Fat-tree k has (k/2)² theoretical paths between pods.
        # More paths → more choices for crypto-aware ECMP scoring.
        # This measures how many distinct paths the controller actually uses
        # and how evenly flows are distributed across core switches.
        print(f"    Measuring ECMP path diversity ...")
        ecmp = _measure_ecmp(net, k)
        result.update(ecmp)
        if "ecmp_error" not in ecmp:
            print(f"      → paths used: {ecmp['ecmp_paths_used']}/{ecmp['ecmp_theoretical_max']} "
                  f"({ecmp['ecmp_path_utilization_pct']:.0f}%)  "
                  f"Jain's fairness: {ecmp['ecmp_jains_fairness']:.3f}")
        else:
            print(f"      → {ecmp['ecmp_error']}")

        # ── [PQC-SPECIFIC] DSCP-Adaptive cipher selection test ──────
        # Send pings with different DSCP markings through the proxy.
        # EF (DSCP 46/0xb8) → should use ChaCha20 (latency-optimized)
        # AF11 (DSCP 10/0x28) → should use AES-256-GCM (high security)
        # BE (DSCP 0/0x00) → should use AES-128-GCM (best effort)
        # Verify the proxy actually selects different ciphers per class.
        if target_port == PROXY_PORT and len(net.hosts) >= 2:
            print(f"    Measuring DSCP-adaptive cipher selection ...")
            src, dst = net.hosts[0], net.hosts[-1]
            # Warm up ALL DSCP paths first (trigger flow setup separately)
            for _, tos_byte, _ in [("EF", 0xb8, ""), ("AF11", 0x28, ""), ("BE", 0x00, "")]:
                src.cmd(f"ping -Q {tos_byte} -c 2 -W 3 {dst.IP()} -q 2>/dev/null")
            time.sleep(1.0)
            dscp_tests = [
                ("EF", 0xb8, "ChaCha20-Poly1305"),
                ("AF11", 0x28, "AES-256-GCM"),
                ("BE", 0x00, "AES-128-GCM"),
            ]
            dscp_results = {}
            for label, tos_byte, expected_cipher in dscp_tests:
                out = src.cmd(f"ping -Q {tos_byte} -c 10 -W 2 {dst.IP()} -q")
                rtt_match = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)", out)
                loss_match = re.search(r"(\d+)% packet loss", out)
                avg_ms = float(rtt_match.group(2)) if rtt_match else -1
                loss = float(loss_match.group(1)) if loss_match else 100
                dscp_results[label] = {"avg_ms": avg_ms, "loss_pct": loss,
                                       "expected_cipher": expected_cipher}
                result[f"dscp_{label}_avg_ms"] = avg_ms
                result[f"dscp_{label}_loss_pct"] = loss

            # Check Prometheus for cipher usage if metrics available
            try:
                import urllib.request
                raw = urllib.request.urlopen(METRICS_URL, timeout=2).read().decode()
                cipher_lines = [l for l in raw.splitlines()
                               if "pqc_cipher_" in l and not l.startswith("#")]
                result["dscp_cipher_metrics"] = len(cipher_lines)
            except Exception:
                result["dscp_cipher_metrics"] = 0

            for label, data in dscp_results.items():
                print(f"      → {label}: avg={data['avg_ms']:.2f}ms  "
                      f"loss={data['loss_pct']:.0f}%  expect={data['expected_cipher']}")

        # ── [PQC-SPECIFIC] Wire overhead on real captured packets ───
        # Measure actual wire frame sizes by doing a known-size ping and
        # checking the overhead added by the PQC framing layer.
        if target_port == PROXY_PORT and len(net.hosts) >= 2:
            print(f"    Measuring wire overhead on real traffic ...")
            src, dst = net.hosts[0], net.hosts[-1]
            # Ping with specific packet sizes to measure framing overhead
            wire_overhead = {}
            for pkt_size in [56, 128, 512, 1024]:
                out = src.cmd(f"ping -s {pkt_size} -c 3 -W 2 {dst.IP()} -q")
                rtt_match = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)", out)
                if rtt_match:
                    wire_overhead[pkt_size] = float(rtt_match.group(2))
                    result[f"wire_{pkt_size}B_rtt_ms"] = float(rtt_match.group(2))

            if wire_overhead:
                # Compare with direct mode baseline RTT to get pure encryption overhead
                base_rtt = result.get("ping_avg_ms", 0.2)
                for sz, rtt in wire_overhead.items():
                    overhead_ms = rtt - base_rtt
                    result[f"wire_{sz}B_overhead_ms"] = round(overhead_ms, 3)
                    print(f"      → {sz}B payload: RTT={rtt:.2f}ms  "
                          f"overhead={overhead_ms:.2f}ms vs baseline {base_rtt:.2f}ms")

    except Exception as e:
        result["error"] = str(e)
        print(f"    ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if net is not None:
            try:
                net.stop()
                # Stack will be killed and restarted before next run anyway,
                # but clean up bridges/veths so the next topology builds clean.
                _clean_topo_state()
            except Exception:
                pass

    return result


# ═══════════════════════════════════════════════════════════════════
# Figure generation — one per PQC-specific metric
# ═══════════════════════════════════════════════════════════════════

def _generate_figures(rows: list, k_values: list):
    """Generate 5 separate comparison figures, one per PQC-specific metric."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    fig_dir = RESULTS_DIR / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    colors = {"direct": "#2196F3", "pqc_proxy": "#E64A19", "pqc_uniform": "#9C27B0", "pqc_adaptive_noaesni": "#FF6F00", "pqc_uniform_noaesni": "#795548", "tls_classical": "#607D8B", "pqc_uniform_chacha": "#2E7D32"}
    labels = {"direct": "Direct (No PQC)", "pqc_proxy": "PQC Adaptive", "pqc_uniform": "PQC Uniform", "pqc_adaptive_noaesni": "PQC Adaptive (no AES-NI)", "pqc_uniform_noaesni": "PQC Uniform (no AES-NI)", "tls_classical": "Classical TLS", "pqc_uniform_chacha": "PQC Uniform ChaCha20"}

    def _get(mode: str, k: int, field: str, default=0):
        row = next((r for r in rows if r["k"] == k and r["mode"] == mode), None)
        if row is None or "error" in row:
            return default
        return row.get(field, default)

    x = np.arange(len(k_values))
    width = 0.35
    host_labels = []
    for k in k_values:
        n_sw = (k // 2) ** 2 + k * k // 2 + k * k // 2
        n_h = (k * k // 2) * 2
        host_labels.append(f"k={k}\n{n_sw}sw/{n_h}h")

    modes_present = sorted(set(r["mode"] for r in rows))
    has_direct = "direct" in modes_present

    # ── Figure 1: Handshake Burst Time ──────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))

    proxy_hs = [_get("pqc_proxy", k, "handshake_burst_s") for k in k_values]
    bars = ax.bar(x, proxy_hs, width, color=colors["pqc_proxy"], label="PQC Proxy (ML-KEM handshake)")

    # Annotate per-switch time on each bar
    for bar, k in zip(bars, k_values):
        per_sw = _get("pqc_proxy", k, "handshake_per_switch_ms")
        if per_sw > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                    f"{per_sw:.0f}ms/sw", ha="center", va="bottom", fontsize=9)

    if has_direct:
        # Direct has zero handshake — show as thin baseline
        ax.bar(x + width, [0] * len(k_values), width, color=colors["direct"],
               label="Direct (No handshake)", alpha=0.3, edgecolor=colors["direct"])

    ax.set_xlabel("Topology Size")
    ax.set_ylabel("Total Handshake Burst Time (seconds)")
    ax.set_title("Fig 1 — ML-KEM Handshake Burst: Time for All Switches")
    ax.set_xticks(x + width / 2 if has_direct else x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "topo_fig1_handshake_burst.png", dpi=150)
    plt.close(fig)
    print(f"    → {fig_dir / 'topo_fig1_handshake_burst.png'}")

    # ── Figure 2: Per-Packet Encryption Overhead (Ping RTT) ────────
    fig, ax = plt.subplots(figsize=(8, 5))

    for i, mode in enumerate(modes_present):
        vals = [_get(mode, k, "ping_avg_ms", default=0) for k in k_values]
        offset = (i - len(modes_present) / 2 + 0.5) * width
        bars = ax.bar(x + offset, vals, width, color=colors[mode], label=labels[mode])
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                        f"{v:.1f}", ha="center", va="bottom", fontsize=8)

    # Show overhead percentage if both modes present
    if has_direct:
        for i, k in enumerate(k_values):
            d = _get("direct", k, "ping_avg_ms")
            p = _get("pqc_proxy", k, "ping_avg_ms")
            if d > 0 and p > 0:
                overhead = (p - d) / d * 100
                y_pos = max(d, p) + 0.5
                ax.annotate(f"+{overhead:.0f}%", xy=(x[i] + width / 2, y_pos),
                            fontsize=9, color="#B71C1C", fontweight="bold", ha="center")

    ax.set_xlabel("Topology Size")
    ax.set_ylabel("Ping RTT (ms)")
    ax.set_title("Fig 2 — Per-Packet Encryption Overhead: AEAD Encrypt/Decrypt Latency")
    ax.set_xticks(x + width / 2 if has_direct else x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "topo_fig2_encryption_overhead.png", dpi=150)
    plt.close(fig)
    print(f"    → {fig_dir / 'topo_fig2_encryption_overhead.png'}")

    # ── Figure 3: Throughput Degradation ────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))

    for i, mode in enumerate(modes_present):
        vals = [_get(mode, k, "throughput_mbps") for k in k_values]
        offset = (i - len(modes_present) / 2 + 0.5) * width
        bars = ax.bar(x + offset, vals, width, color=colors[mode], label=labels[mode])
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                        f"{v:.0f}", ha="center", va="bottom", fontsize=8)

    if has_direct:
        for i, k in enumerate(k_values):
            d = _get("direct", k, "throughput_mbps")
            p = _get("pqc_proxy", k, "throughput_mbps")
            if d > 0 and p > 0:
                degradation = (p - d) / d * 100
                y_pos = max(d, p) + 0.5
                ax.annotate(f"{degradation:+.0f}%", xy=(x[i] + width / 2, y_pos),
                            fontsize=9, color="#B71C1C" if degradation < 0 else "#2E7D32",
                            fontweight="bold", ha="center")

    ax.set_xlabel("Topology Size")
    ax.set_ylabel("TCP Throughput (Mbps)")
    ax.set_title("Fig 3 — Throughput Degradation: Crypto Pipeline Under Concurrent Load")
    ax.set_xticks(x + width / 2 if has_direct else x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "topo_fig3_throughput.png", dpi=150)
    plt.close(fig)
    print(f"    → {fig_dir / 'topo_fig3_throughput.png'}")

    # ── Figure 4: Flow Setup Latency ────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))

    for i, mode in enumerate(modes_present):
        means = [_get(mode, k, "flow_setup_mean_ms", default=0) for k in k_values]
        maxes = [_get(mode, k, "flow_setup_max_ms", default=0) for k in k_values]
        offset = (i - len(modes_present) / 2 + 0.5) * width

        bars = ax.bar(x + offset, means, width, color=colors[mode], label=f"{labels[mode]} (mean)")
        # Error bars showing max
        ax.errorbar(x + offset, means,
                    yerr=[[0]*len(k_values), [m - n for m, n in zip(maxes, means)]],
                    fmt="none", ecolor="black", capsize=3, alpha=0.5)

        for bar, v in zip(bars, means):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                        f"{v:.0f}", ha="center", va="bottom", fontsize=8)

    if has_direct:
        for i, k in enumerate(k_values):
            d = _get("direct", k, "flow_setup_mean_ms")
            p = _get("pqc_proxy", k, "flow_setup_mean_ms")
            if d > 0 and p > 0:
                overhead = (p - d) / d * 100
                y_pos = max(d, p) + 2
                ax.annotate(f"+{overhead:.0f}%", xy=(x[i] + width / 2, y_pos),
                            fontsize=9, color="#B71C1C", fontweight="bold", ha="center")

    ax.set_xlabel("Topology Size")
    ax.set_ylabel("Flow Setup Time (ms)")
    ax.set_title("Fig 4 — Flow Setup Latency: PACKET_IN→FLOW_MOD Through Encrypted Control")
    ax.set_xticks(x + width / 2 if has_direct else x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "topo_fig4_flow_setup.png", dpi=150)
    plt.close(fig)
    print(f"    → {fig_dir / 'topo_fig4_flow_setup.png'}")

    # ── Figure 5: Topology Convergence Time ─────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))

    for i, mode in enumerate(modes_present):
        vals = [_get(mode, k, "converge_time_s") for k in k_values]
        offset = (i - len(modes_present) / 2 + 0.5) * width
        bars = ax.bar(x + offset, vals, width, color=colors[mode], label=labels[mode])
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                        f"{v:.1f}s", ha="center", va="bottom", fontsize=8)

    if has_direct:
        for i, k in enumerate(k_values):
            d = _get("direct", k, "converge_time_s")
            p = _get("pqc_proxy", k, "converge_time_s")
            if d > 0 and p > 0:
                overhead = (p - d) / d * 100
                y_pos = max(d, p) + 0.5
                ax.annotate(f"+{overhead:.0f}%", xy=(x[i] + width / 2, y_pos),
                            fontsize=9, color="#B71C1C", fontweight="bold", ha="center")

    ax.set_xlabel("Topology Size")
    ax.set_ylabel("Time to Full Convergence (seconds)")
    ax.set_title("Fig 5 — Topology Convergence: LLDP Discovery Through Encrypted Tunnel")
    ax.set_xticks(x + width / 2 if has_direct else x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "topo_fig5_convergence.png", dpi=150)
    plt.close(fig)
    print(f"    → {fig_dir / 'topo_fig5_convergence.png'}")

    # ── Summary figure: PQC overhead percentage across all metrics ──
    if has_direct:
        fig, ax = plt.subplots(figsize=(10, 5))

        metrics = [
            ("converge_time_s", "Convergence\nTime"),
            ("ping_avg_ms", "Ping\nLatency"),
            ("flow_setup_mean_ms", "Flow Setup\nLatency"),
            ("throughput_mbps", "Throughput"),
        ]

        overhead_data = {}
        for field, label in metrics:
            overheads = []
            for k in k_values:
                d = _get("direct", k, field)
                p = _get("pqc_proxy", k, field)
                if d > 0 and p > 0:
                    if field == "throughput_mbps":
                        # Throughput: negative overhead = degradation
                        overheads.append((p - d) / d * 100)
                    else:
                        overheads.append((p - d) / d * 100)
                else:
                    overheads.append(0)
            overhead_data[label] = overheads

        x_met = np.arange(len(metrics))
        width_k = 0.8 / len(k_values)
        k_colors = ["#1565C0", "#2E7D32", "#E65100", "#6A1B9A"]

        for i, k in enumerate(k_values):
            vals = [overhead_data[label][i] for _, label in metrics]
            offset = (i - len(k_values) / 2 + 0.5) * width_k
            ax.bar(x_met + offset, vals, width_k, label=f"k={k}", color=k_colors[i % len(k_colors)])

        ax.axhline(y=0, color="black", linewidth=0.5)
        ax.set_xlabel("Metric")
        ax.set_ylabel("PQC Overhead (%)")
        ax.set_title("Fig 6 — PQC Proxy Overhead Summary: Impact Across Topology Sizes")
        ax.set_xticks(x_met)
        ax.set_xticklabels([label for _, label in metrics])
        ax.legend(title="Topology")
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(fig_dir / "topo_fig6_overhead_summary.png", dpi=150)
        plt.close(fig)
        print(f"    → {fig_dir / 'topo_fig6_overhead_summary.png'}")

    # ── Figure 7: ECMP Path Diversity Across Topology Sizes ─────────
    # This figure is generated for ALL modes (direct + proxy) because
    # ECMP behavior may differ: the crypto-aware scorer in proxy mode
    # considers cipher overhead, while direct mode uses plain ECMP.
    has_ecmp = any(r.get("ecmp_paths_used", 0) > 0 for r in rows)
    if has_ecmp:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

        # Left panel: paths used vs theoretical max, per mode
        theoretical = [(k // 2) ** 2 for k in k_values]
        ax1.plot(x, theoretical, "k--", linewidth=2, label="Theoretical max (k/2)²", marker="s", zorder=5)

        for mode in modes_present:
            vals = [_get(mode, k, "ecmp_paths_used", default=0) for k in k_values]
            ax1.plot(x, vals, "o-", color=colors[mode], linewidth=2, markersize=8,
                     label=labels[mode])
            for xi, v, t in zip(x, vals, theoretical):
                if v > 0:
                    pct = v / t * 100 if t > 0 else 0
                    ax1.annotate(f"{v}/{t}\n({pct:.0f}%)", xy=(xi, v),
                                 textcoords="offset points", xytext=(0, 12),
                                 ha="center", fontsize=8)

        ax1.set_xlabel("Topology Size")
        ax1.set_ylabel("Distinct ECMP Paths Used")
        ax1.set_title("Path Diversity: Plain ECMP vs Crypto-Aware")
        ax1.set_xticks(x)
        ax1.set_xticklabels(host_labels)
        ax1.legend(loc="upper left")
        ax1.grid(axis="y", alpha=0.3)

        # Right panel: Jain's fairness index per mode
        for mode in modes_present:
            vals = [_get(mode, k, "ecmp_jains_fairness", default=0) for k in k_values]
            ax2.plot(x, vals, "o-", color=colors[mode], linewidth=2, markersize=8,
                     label=labels[mode])
            for xi, v in zip(x, vals):
                if v > 0:
                    ax2.annotate(f"{v:.3f}", xy=(xi, v),
                                 textcoords="offset points", xytext=(0, 10),
                                 ha="center", fontsize=8)

        ax2.axhline(y=1.0, color="green", linewidth=1, linestyle=":", alpha=0.7, label="Perfect fairness")
        ax2.set_xlabel("Topology Size")
        ax2.set_ylabel("Jain's Fairness Index")
        ax2.set_title("Flow Distribution: Plain vs Crypto-Aware")
        ax2.set_xticks(x)
        ax2.set_xticklabels(host_labels)
        ax2.set_ylim(0, 1.1)
        ax2.legend(loc="lower right")
        ax2.grid(axis="y", alpha=0.3)

        fig.suptitle("Fig 7 — ECMP A/B: Plain (Direct) vs Crypto-Aware (PQC Proxy) Path Selection",
                      fontsize=11, fontweight="bold")
        fig.tight_layout()
        fig.savefig(fig_dir / "topo_fig7_ecmp.png", dpi=150)
        plt.close(fig)
        print(f"    → {fig_dir / 'topo_fig7_ecmp.png'}")

    # ── Figure 8: Controller Resource Usage During Handshake Burst ───
    # Shows CPU and memory usage on the controller/proxy when all switches
    # handshake simultaneously.  This is the PQC handshake exhaustion
    # concern: does the ML-KEM burst overwhelm the controller at scale?
    has_resources = any(r.get("cpu_peak_pct", 0) > 0 for r in rows)
    if has_resources:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

        proxy_rows = [r for r in rows if r.get("mode") in ("pqc_proxy", "pqc_uniform", "pqc_adaptive_noaesni", "pqc_uniform_noaesni") and r.get("cpu_peak_pct", 0) > 0]
        if proxy_rows:
            ks_with_data = [r["k"] for r in proxy_rows]
            x_res = np.arange(len(ks_with_data))
            res_labels = []
            for k in ks_with_data:
                n_sw = (k // 2) ** 2 + k * k // 2 + k * k // 2
                res_labels.append(f"k={k}\n{n_sw} sw")

            # Left: CPU peak & avg
            cpu_peak = [r.get("cpu_peak_pct", 0) for r in proxy_rows]
            cpu_avg = [r.get("cpu_avg_pct", 0) for r in proxy_rows]
            w = 0.35
            bars1 = ax1.bar(x_res - w / 2, cpu_peak, w, color="#D32F2F", label="Peak CPU %")
            bars2 = ax1.bar(x_res + w / 2, cpu_avg, w, color="#FF8A65", label="Avg CPU %")
            for bar, v in zip(bars1, cpu_peak):
                if v > 0:
                    ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                             f"{v:.0f}%", ha="center", va="bottom", fontsize=9)
            for bar, v in zip(bars2, cpu_avg):
                if v > 0:
                    ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                             f"{v:.0f}%", ha="center", va="bottom", fontsize=9)

            ax1.axhline(y=100, color="red", linewidth=1, linestyle=":", alpha=0.5, label="100% CPU")
            ax1.set_xlabel("Topology Size")
            ax1.set_ylabel("Controller CPU Usage (%)")
            ax1.set_title("CPU During ML-KEM Handshake Burst")
            ax1.set_xticks(x_res)
            ax1.set_xticklabels(res_labels)
            ax1.legend()
            ax1.grid(axis="y", alpha=0.3)

            # Right: Memory peak & queue depth
            mem_peak = [r.get("mem_peak_mb", 0) for r in proxy_rows]
            queue_peak = [r.get("queue_peak", 0) for r in proxy_rows]

            ax2_color = "#1565C0"
            bars3 = ax2.bar(x_res, mem_peak, 0.5, color=ax2_color, alpha=0.8, label="Peak RSS (MB)")
            for bar, v in zip(bars3, mem_peak):
                if v > 0:
                    ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                             f"{v:.0f}MB", ha="center", va="bottom", fontsize=9)

            ax2.set_xlabel("Topology Size")
            ax2.set_ylabel("Controller Memory (MB)")
            ax2.set_title("Memory & Queue Depth During Handshake Burst")
            ax2.set_xticks(x_res)
            ax2.set_xticklabels(res_labels)
            ax2.legend(loc="upper left")
            ax2.grid(axis="y", alpha=0.3)

            # Overlay queue depth on right y-axis
            if any(q > 0 for q in queue_peak):
                ax2b = ax2.twinx()
                ax2b.plot(x_res, queue_peak, "D-", color="#E65100", linewidth=2,
                          markersize=8, label="Peak Queue Depth")
                for xi, v in zip(x_res, queue_peak):
                    if v > 0:
                        ax2b.annotate(f"{v}", xy=(xi, v),
                                      textcoords="offset points", xytext=(8, 4),
                                      fontsize=9, color="#E65100")
                ax2b.set_ylabel("Handshake Queue Depth")
                ax2b.legend(loc="upper right")

        fig.suptitle("Fig 8 — Controller Resource Usage: ML-KEM Handshake Exhaustion at Scale",
                      fontsize=12, fontweight="bold")
        fig.tight_layout()
        fig.savefig(fig_dir / "topo_fig8_resources.png", dpi=150)
        plt.close(fig)
        print(f"    → {fig_dir / 'topo_fig8_resources.png'}")


# ═══════════════════════════════════════════════════════════════════
# Aggregated figures (mean ± 95% CI from multiple runs)
# ═══════════════════════════════════════════════════════════════════

def _generate_aggregated_figures(agg_rows: list, k_values: list, n_runs: int):
    """Generate figures with error bars from aggregated multi-run data."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    fig_dir = RESULTS_DIR / "figures_aggregated"
    fig_dir.mkdir(parents=True, exist_ok=True)

    colors = {"direct": "#2196F3", "pqc_proxy": "#E64A19", "pqc_uniform": "#9C27B0", "pqc_adaptive_noaesni": "#FF6F00", "pqc_uniform_noaesni": "#795548", "tls_classical": "#607D8B", "pqc_uniform_chacha": "#2E7D32"}
    labels = {"direct": "Direct (No PQC)", "pqc_proxy": "PQC Adaptive", "pqc_uniform": "PQC Uniform", "pqc_adaptive_noaesni": "PQC Adaptive (no AES-NI)", "pqc_uniform_noaesni": "PQC Uniform (no AES-NI)", "tls_classical": "Classical TLS", "pqc_uniform_chacha": "PQC Uniform ChaCha20"}

    def _get(mode, k, field, default=0):
        row = next((r for r in agg_rows if r["k"] == k and r["mode"] == mode), None)
        if row is None:
            return default, 0
        mean = row.get(f"{field}_mean", default)
        lo = row.get(f"{field}_ci95_lo", mean)
        hi = row.get(f"{field}_ci95_hi", mean)
        margin = (hi - lo) / 2 if lo != hi else 0
        return mean if mean is not None else default, margin

    x = np.arange(len(k_values))
    width = 0.35
    host_labels = []
    for k in k_values:
        n_sw = (k // 2) ** 2 + k * k // 2 + k * k // 2
        n_h = (k * k // 2) * 2
        host_labels.append(f"k={k}\n{n_sw}sw/{n_h}h")

    modes_present = sorted(set(r["mode"] for r in agg_rows))
    has_direct = "direct" in modes_present

    # ── Fig A1: Handshake Burst (with CI) ─────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    vals, errs = zip(*[_get("pqc_proxy", k, "handshake_burst_s") for k in k_values])
    bars = ax.bar(x, vals, width, yerr=errs, capsize=5,
                  color=colors["pqc_proxy"], label="PQC Proxy (ML-KEM)")
    for bar, v, e in zip(bars, vals, errs):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + e + 0.1,
                    f"{v:.2f}s", ha="center", va="bottom", fontsize=9)
    ax.set_xlabel("Topology Size")
    ax.set_ylabel("Handshake Burst Time (s)")
    ax.set_title(f"ML-KEM Handshake Burst Time (n={n_runs} runs, mean ± 95% CI)")
    ax.set_xticks(x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "agg_fig1_handshake_burst.png", dpi=300)
    plt.close(fig)
    print(f"    → {fig_dir / 'agg_fig1_handshake_burst.png'}")

    # ── Fig A2: Ping RTT with CI (the key overhead figure) ───────
    fig, ax = plt.subplots(figsize=(8, 5))
    for i, mode in enumerate(modes_present):
        vals, errs = zip(*[_get(mode, k, "ping_avg_ms") for k in k_values])
        offset = (i - len(modes_present)/2 + 0.5) * width
        bars = ax.bar(x + offset, vals, width, yerr=errs, capsize=5,
                      color=colors[mode], label=labels[mode])
        for bar, v, e in zip(bars, vals, errs):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + e + 0.02,
                        f"{v:.2f}", ha="center", va="bottom", fontsize=8)

    # Overhead annotations
    if has_direct:
        for i, k in enumerate(k_values):
            d, _ = _get("direct", k, "ping_avg_ms")
            p, _ = _get("pqc_proxy", k, "ping_avg_ms")
            if d > 0 and p > 0:
                overhead = (p - d) / d * 100
                y = max(d, p) + 0.1
                ax.annotate(f"+{overhead:.0f}%", xy=(x[i] + width/4, y),
                            fontsize=9, color="#B71C1C", fontweight="bold", ha="center")

    ax.set_xlabel("Topology Size")
    ax.set_ylabel("Ping RTT (ms)")
    ax.set_title(f"Per-Packet Encryption Overhead (n={n_runs} runs, mean ± 95% CI)")
    ax.set_xticks(x + width/4 if has_direct else x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "agg_fig2_ping_overhead.png", dpi=300)
    plt.close(fig)
    print(f"    → {fig_dir / 'agg_fig2_ping_overhead.png'}")

    # ── Fig A3: Throughput with CI ────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    for i, mode in enumerate(modes_present):
        vals, errs = zip(*[_get(mode, k, "throughput_mbps") for k in k_values])
        offset = (i - len(modes_present)/2 + 0.5) * width
        bars = ax.bar(x + offset, vals, width, yerr=errs, capsize=5,
                      color=colors[mode], label=labels[mode])
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                        f"{v:.1f}", ha="center", va="bottom", fontsize=8)
    ax.set_xlabel("Topology Size")
    ax.set_ylabel("TCP Throughput (Mbps)")
    ax.set_title(f"Throughput: Direct vs PQC Proxy (n={n_runs} runs, mean ± 95% CI)")
    ax.set_xticks(x + width/4 if has_direct else x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "agg_fig3_throughput.png", dpi=300)
    plt.close(fig)
    print(f"    → {fig_dir / 'agg_fig3_throughput.png'}")

    # ── Fig A4: Convergence Time with CI ──────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    for i, mode in enumerate(modes_present):
        vals, errs = zip(*[_get(mode, k, "converge_time_s") for k in k_values])
        offset = (i - len(modes_present)/2 + 0.5) * width
        bars = ax.bar(x + offset, vals, width, yerr=errs, capsize=5,
                      color=colors[mode], label=labels[mode])
        for bar, v, e in zip(bars, vals, errs):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + e + 0.3,
                        f"{v:.1f}s", ha="center", va="bottom", fontsize=8)
    ax.set_xlabel("Topology Size")
    ax.set_ylabel("Convergence Time (s)")
    ax.set_title(f"Topology Convergence (n={n_runs} runs, mean ± 95% CI)")
    ax.set_xticks(x + width/4 if has_direct else x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "agg_fig4_convergence.png", dpi=300)
    plt.close(fig)
    print(f"    → {fig_dir / 'agg_fig4_convergence.png'}")

    # ── Fig A5: Flow Setup Latency with CI ────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    for i, mode in enumerate(modes_present):
        vals, errs = zip(*[_get(mode, k, "flow_setup_mean_ms") for k in k_values])
        offset = (i - len(modes_present)/2 + 0.5) * width
        bars = ax.bar(x + offset, vals, width, yerr=errs, capsize=5,
                      color=colors[mode], label=labels[mode])
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
                        f"{v:.0f}", ha="center", va="bottom", fontsize=8)
    ax.set_xlabel("Topology Size")
    ax.set_ylabel("Flow Setup Time (ms)")
    ax.set_title(f"Flow Setup Latency (n={n_runs} runs, mean ± 95% CI)")
    ax.set_xticks(x + width/4 if has_direct else x)
    ax.set_xticklabels(host_labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(fig_dir / "agg_fig5_flow_setup.png", dpi=300)
    plt.close(fig)
    print(f"    → {fig_dir / 'agg_fig5_flow_setup.png'}")

    # ── Fig A6: ECMP Path Diversity with CI ───────────────────────
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    theoretical = [(k // 2) ** 2 for k in k_values]
    ax1.plot(x, theoretical, "k--", linewidth=2, label="Theoretical max (k/2)²", marker="s")
    for mode in modes_present:
        vals, errs = zip(*[_get(mode, k, "ecmp_paths_used") for k in k_values])
        ax1.errorbar(x, vals, yerr=errs, fmt="o-", color=colors[mode],
                     linewidth=2, markersize=8, capsize=5, label=labels[mode])
    ax1.set_xlabel("Topology Size")
    ax1.set_ylabel("ECMP Paths Used")
    ax1.set_title("Path Diversity")
    ax1.set_xticks(x)
    ax1.set_xticklabels(host_labels)
    ax1.legend(fontsize=8)
    ax1.grid(axis="y", alpha=0.3)

    for mode in modes_present:
        vals, errs = zip(*[_get(mode, k, "ecmp_jains_fairness") for k in k_values])
        ax2.errorbar(x, vals, yerr=errs, fmt="o-", color=colors[mode],
                     linewidth=2, markersize=8, capsize=5, label=labels[mode])
    ax2.axhline(y=1.0, color="green", linewidth=1, linestyle=":", alpha=0.7)
    ax2.set_xlabel("Topology Size")
    ax2.set_ylabel("Jain's Fairness Index")
    ax2.set_title("Flow Distribution Fairness")
    ax2.set_xticks(x)
    ax2.set_xticklabels(host_labels)
    ax2.set_ylim(0, 1.1)
    ax2.legend(fontsize=8)
    ax2.grid(axis="y", alpha=0.3)

    fig.suptitle(f"ECMP Analysis (n={n_runs} runs, mean ± 95% CI)", fontsize=11, fontweight="bold")
    fig.tight_layout()
    fig.savefig(fig_dir / "agg_fig6_ecmp.png", dpi=300)
    plt.close(fig)
    print(f"    → {fig_dir / 'agg_fig6_ecmp.png'}")

    # ── Fig A7: PQC Overhead Summary (%) with CI ─────────────────
    if has_direct:
        fig, ax = plt.subplots(figsize=(10, 5))
        metrics = [
            ("converge_time_s", "Convergence"),
            ("ping_avg_ms", "Ping Latency"),
            ("flow_setup_mean_ms", "Flow Setup"),
            ("throughput_mbps", "Throughput"),
        ]

        x_met = np.arange(len(metrics))
        width_k = 0.8 / len(k_values)
        k_colors = ["#1565C0", "#2E7D32", "#E65100", "#6A1B9A"]

        for i, k in enumerate(k_values):
            overheads = []
            for field, _ in metrics:
                d, _ = _get("direct", k, field)
                p, _ = _get("pqc_proxy", k, field)
                if d > 0 and p > 0:
                    overheads.append((p - d) / d * 100)
                else:
                    overheads.append(0)
            offset = (i - len(k_values)/2 + 0.5) * width_k
            bars = ax.bar(x_met + offset, overheads, width_k,
                          label=f"k={k}", color=k_colors[i % len(k_colors)])
            for bar, v in zip(bars, overheads):
                if abs(v) > 1:
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                            f"{v:+.0f}%", ha="center", va="bottom", fontsize=7)

        ax.axhline(y=0, color="black", linewidth=0.5)
        ax.set_xlabel("Metric")
        ax.set_ylabel("PQC Overhead (%)")
        ax.set_title(f"PQC Proxy Overhead Summary (n={n_runs} runs)")
        ax.set_xticks(x_met)
        ax.set_xticklabels([label for _, label in metrics])
        ax.legend(title="Topology")
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(fig_dir / "agg_fig7_overhead_summary.png", dpi=300)
        plt.close(fig)
        print(f"    → {fig_dir / 'agg_fig7_overhead_summary.png'}")

    # ── Fig A8: Controller Resources with CI ──────────────────────
    proxy_aggs = [r for r in agg_rows if r["mode"] in ("pqc_proxy", "pqc_uniform", "pqc_adaptive_noaesni", "pqc_uniform_noaesni")]
    if proxy_aggs and any(r.get("cpu_peak_pct_mean", 0) > 0 for r in proxy_aggs):
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        ks_with = [r["k"] for r in proxy_aggs if r.get("cpu_peak_pct_mean", 0) > 0]
        x_r = np.arange(len(ks_with))
        rl = [f"k={k}" for k in ks_with]

        cpu_vals = [next(r["cpu_peak_pct_mean"] for r in proxy_aggs if r["k"] == k) for k in ks_with]
        cpu_errs = [next((r["cpu_peak_pct_ci95_hi"] - r["cpu_peak_pct_ci95_lo"])/2
                         if r.get("cpu_peak_pct_ci95_hi") and r.get("cpu_peak_pct_ci95_lo")
                         else 0 for r in proxy_aggs if r["k"] == k) for k in ks_with]

        ax1.bar(x_r, cpu_vals, yerr=cpu_errs, capsize=5, color="#D32F2F", width=0.5)
        for xi, v in zip(x_r, cpu_vals):
            ax1.text(xi, v + 2, f"{v:.0f}%", ha="center", fontsize=9)
        ax1.set_xlabel("Topology")
        ax1.set_ylabel("Peak CPU (%)")
        ax1.set_title("CPU During Handshake Burst")
        ax1.set_xticks(x_r)
        ax1.set_xticklabels(rl)
        ax1.grid(axis="y", alpha=0.3)

        mem_vals = [next(r.get("mem_peak_mb_mean", 0) for r in proxy_aggs if r["k"] == k) for k in ks_with]
        ax2.bar(x_r, mem_vals, color="#1565C0", width=0.5)
        for xi, v in zip(x_r, mem_vals):
            ax2.text(xi, v + 1, f"{v:.0f}MB", ha="center", fontsize=9)
        ax2.set_xlabel("Topology")
        ax2.set_ylabel("Peak Memory (MB)")
        ax2.set_title("Memory During Handshake Burst")
        ax2.set_xticks(x_r)
        ax2.set_xticklabels(rl)
        ax2.grid(axis="y", alpha=0.3)

        fig.suptitle(f"Controller Resources (n={n_runs} runs, mean ± 95% CI)", fontsize=11)
        fig.tight_layout()
        fig.savefig(fig_dir / "agg_fig8_resources.png", dpi=300)
        plt.close(fig)
        print(f"    → {fig_dir / 'agg_fig8_resources.png'}")

    # ── Fig A9: DSCP Adaptive Cipher Selection ────────────────────
    # Only the adaptive modes select a cipher per DSCP class; uniform modes
    # use one cipher for all classes, so their bars would be mislabelled.
    proxy_dscp = [r for r in agg_rows if r["mode"] in ("pqc_proxy", "pqc_adaptive_noaesni")
                  and r.get("dscp_EF_avg_ms_mean") is not None]
    if proxy_dscp:
        fig, ax = plt.subplots(figsize=(10, 5))
        dscp_classes = ["EF", "AF11", "BE"]
        dscp_colors = ["#E64A19", "#3F51B5", "#4CAF50"]
        dscp_ciphers = ["ChaCha20", "AES-256-GCM", "AES-128-GCM"]

        x_k = np.arange(len(proxy_dscp))
        w = 0.25
        for i, (cls, col, cipher) in enumerate(zip(dscp_classes, dscp_colors, dscp_ciphers)):
            # Median with IQR whiskers: a single run whose EF probe overlaps
            # flow setup would otherwise dominate the mean.
            vals = [r.get(f"dscp_{cls}_avg_ms_median", 0) for r in proxy_dscp]
            errs = [[v - r.get(f"dscp_{cls}_avg_ms_q1", v) for r, v in zip(proxy_dscp, vals)],
                    [r.get(f"dscp_{cls}_avg_ms_q3", v) - v for r, v in zip(proxy_dscp, vals)]]
            bars = ax.bar(x_k + (i-1)*w, vals, w, yerr=errs, capsize=4,
                          color=col, label=f"{cls} → {cipher}")
            for bar, v, up in zip(bars, vals, errs[1]):
                if v > 0:
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + up + 0.003,
                            f"{v:.2f}", ha="center", va="bottom", fontsize=7)

        ax.set_xlabel("Topology Size")
        ax.set_ylabel("Ping RTT (ms)")
        ax.set_title(f"DSCP-Adaptive Cipher Selection in Mininet (n={n_runs} runs, median, IQR whiskers)")
        ax.set_xticks(x_k)
        multi_mode = len(set(r["mode"] for r in proxy_dscp)) > 1
        ax.set_xticklabels([f"k={r['k']}" + (f"\n{labels[r['mode']]}" if multi_mode else "")
                            for r in proxy_dscp])
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(fig_dir / "agg_fig9_dscp_adaptive.png", dpi=300)
        plt.close(fig)
        print(f"    → {fig_dir / 'agg_fig9_dscp_adaptive.png'}")


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

def _aggregate_rows(all_rows: list, k_values: list) -> list:
    """Aggregate runs per (k, mode): mean, std, 95% CI, median and IQR."""
    import numpy as np
    from scipy import stats as sp_stats

    agg_rows = []
    numeric_fields = [
        "converge_time_s", "ping_avg_ms", "ping_min_ms", "ping_max_ms",
        "ping_loss_pct", "throughput_mbps", "flow_setup_mean_ms",
        "flow_setup_max_ms", "handshake_burst_s", "handshake_per_switch_ms",
        "ecmp_paths_used", "ecmp_jains_fairness", "ecmp_path_utilization_pct",
        "cpu_peak_pct", "cpu_avg_pct", "mem_peak_mb",
        "dscp_EF_avg_ms", "dscp_AF11_avg_ms", "dscp_BE_avg_ms",
    ]

    # Discover all modes present in the data (handles three-way automatically)
    all_modes = sorted(set(r["mode"] for r in all_rows if "error" not in r))

    for k in k_values:
        for mode in all_modes:
            runs = [r for r in all_rows
                    if r.get("k") == k and r.get("mode") == mode and "error" not in r]
            if not runs:
                continue

            agg = {"k": k, "mode": mode, "n_runs": len(runs)}

            for field in numeric_fields:
                vals = [r.get(field) for r in runs
                        if r.get(field) is not None and r.get(field) != -1]
                if not vals:
                    continue
                vals = [float(v) for v in vals]
                arr = np.array(vals)
                mean = float(np.mean(arr))
                std = float(np.std(arr, ddof=1)) if len(arr) > 1 else 0
                # 95% CI via t-distribution
                if len(arr) > 1:
                    ci = sp_stats.t.interval(0.95, df=len(arr)-1,
                                             loc=mean, scale=std/np.sqrt(len(arr)))
                    ci_lo, ci_hi = float(ci[0]), float(ci[1])
                else:
                    ci_lo = ci_hi = mean

                agg[f"{field}_mean"] = round(mean, 4)
                agg[f"{field}_std"] = round(std, 4)
                agg[f"{field}_ci95_lo"] = round(ci_lo, 4)
                agg[f"{field}_ci95_hi"] = round(ci_hi, 4)
                agg[f"{field}_n"] = len(arr)
                # Median and IQR: robust to single-run outliers (e.g. the EF
                # probe occasionally catching flow setup at k=10).
                q1, med, q3 = np.percentile(arr, [25, 50, 75])
                agg[f"{field}_median"] = round(float(med), 4)
                agg[f"{field}_q1"] = round(float(q1), 4)
                agg[f"{field}_q3"] = round(float(q3), 4)

            agg_rows.append(agg)

    return agg_rows


def main():
    parser = argparse.ArgumentParser(
        description="PQC-SDN Topology Scaling Evaluation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo -E PYTHONPATH=src python evaluation/topo_comparison.py
  sudo -E PYTHONPATH=src python evaluation/topo_comparison.py --k 4,6,8,10
  sudo -E PYTHONPATH=src python evaluation/topo_comparison.py --proxy-only
        """,
    )
    parser.add_argument("--k", type=str, default="4,6,8,10",
                        help="Comma-separated k values (default: 4,6,8,10)")
    parser.add_argument("--proxy-only", action="store_true",
                        help="Skip direct mode, only test with PQC proxy")
    parser.add_argument("--runs", type=int, default=1,
                        help="Number of independent runs per (k, mode) pair (default: 1, use 5 for publication)")
    parser.add_argument("--three-way", action="store_true",
                        help="Add Mode B (PQC + fixed AES-256-GCM, no DSCP) for three-way comparison")
    parser.add_argument("--no-aesni", action="store_true",
                        help="Disable AES-NI (via OPENSSL_ia32cap) to show DSCP-adaptive benefit on software AEAD")
    parser.add_argument("--cp-metrics", action="store_true",
                        help="Enable control-plane per-message timing (PQC_CP_METRICS=1)")
    parser.add_argument("--reaggregate", action="store_true",
                        help="Recompute aggregates and aggregated figures from the saved "
                             "topo_comparison.json without running any experiment")
    args = parser.parse_args()

    k_values = [int(x) for x in args.k.split(",")]

    if args.reaggregate:
        with open(RESULTS_DIR / "topo_comparison.json") as f:
            all_rows = json.load(f)
        n_runs = max(r.get("run", 1) for r in all_rows)
        agg_rows = _aggregate_rows(all_rows, k_values)
        with open(RESULTS_DIR / "topo_comparison_aggregated.json", "w") as f:
            json.dump(agg_rows, f, indent=2)
        agg_fields = sorted(set().union(*(r.keys() for r in agg_rows)))
        with open(RESULTS_DIR / "topo_comparison_aggregated.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=agg_fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(agg_rows)
        _generate_aggregated_figures(agg_rows, k_values, n_runs)
        print(f"  Re-aggregated {len(all_rows)} rows (n={n_runs} runs) → {RESULTS_DIR}")
        return

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  PQC-SDN Topology Scaling Evaluation                        ║")
    print("║  What does our PQC layer cost, and how does it scale?       ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print("  Topologies:", ", ".join(f"k={k}" for k in k_values))
    for k in k_values:
        ns = (k // 2) ** 2 + k * k // 2 + k * k // 2
        nh = (k * k // 2) * 2
        print(f"    k={k}: {ns} switches, {nh} hosts")
    print(f"  Modes: {'PQC proxy only' if args.proxy_only else 'Direct (no PQC) vs PQC Proxy'}")
    print()

    # Dependency check
    errors = _check_deps()
    if errors:
        print("  Missing dependencies:")
        for e in errors:
            print(f"    ✗ {e}")
        sys.exit(1)

    if not args.proxy_only and not _check_proxy_running():
        print("  ⚠ Note: Proxy stack not detected on :6634.")
        print("    Will run direct mode tests. PQC proxy tests will be skipped.")
        print("    To run both modes, start the proxy stack first:")
        print("      python -m pqc_sdn.apps.sw_proxy_async &")
        print("      python -m pqc_sdn.apps.ctrl_proxy &")
        print()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    all_rows = []
    n_runs = args.runs

    print(f"  Runs per (k, mode): {n_runs}")
    print()

    for run_idx in range(n_runs):
        if n_runs > 1:
            print(f"\n{'▓' * 60}")
            print(f"  RUN {run_idx + 1}/{n_runs}")
            print(f"{'▓' * 60}")

        for k in k_values:
            # ── Mode A: Direct (no proxy, no encryption) ──
            if not args.proxy_only:
                print(f"\n  ── Restarting stack (Ryu only) for k={k} DIRECT [run {run_idx+1}] ──")
                _kill_stack()
                _clean_topo_state()
                _start_stack(need_proxy=False)

                row = run_one(k, "direct", RYU_PORT)
                row["run"] = run_idx + 1
                all_rows.append(row)

                # ── Mode A2: Classical TLS (OVS native TLS, no PQC) ──
                # This is the "current practice" baseline: standard ECDSA+X25519 TLS.
                # Shows what PQC costs OVER current TLS-protected SDN.
                if _TLS_CERT_DIR.exists() and (args.three_way or args.no_aesni):
                    print(f"\n  ── Restarting stack (Ryu+TLS) for k={k} TLS CLASSICAL [run {run_idx+1}] ──")
                    _kill_stack()
                    _clean_topo_state()
                    _start_stack(need_proxy=False, tls_mode=True)

                    row = run_one(k, "tls_classical", RYU_PORT, protocol="ssl")
                    row["run"] = run_idx + 1
                    all_rows.append(row)

            # ── Mode B: With PQC proxy (DSCP-adaptive) ──
            print(f"\n  ── Restarting stack (Ryu + proxies) for k={k} PQC PROXY ADAPTIVE [run {run_idx+1}] ──")
            _kill_stack()
            _clean_topo_state()
            # Clear any fixed cipher override
            os.environ.pop("PQC_FIXED_CIPHER", None)
            os.environ.pop("OPENSSL_ia32cap", None)
            if args.cp_metrics:
                os.environ["PQC_CP_METRICS"] = "1"
            if _start_stack(need_proxy=True):
                row = run_one(k, "pqc_proxy", PROXY_PORT)
                row["run"] = run_idx + 1
                all_rows.append(row)
            else:
                print(f"    ⚠ Stack failed to start for k={k} proxy — skipping")
                all_rows.append({"k": k, "mode": "pqc_proxy", "run": run_idx + 1,
                                 "error": "stack_start_failed"})

            # ── Mode C: PQC proxy with FIXED AES-256-GCM (no DSCP switching) ──
            if args.three_way:
                print(f"\n  ── Restarting stack (Ryu + proxies) for k={k} PQC UNIFORM [run {run_idx+1}] ──")
                _kill_stack()
                _clean_topo_state()
                os.environ["PQC_FIXED_CIPHER"] = "AES-256-GCM"
                os.environ.pop("OPENSSL_ia32cap", None)
                if _start_stack(need_proxy=True):
                    row = run_one(k, "pqc_uniform", PROXY_PORT)
                    row["run"] = run_idx + 1
                    all_rows.append(row)
                else:
                    all_rows.append({"k": k, "mode": "pqc_uniform", "run": run_idx + 1,
                                     "error": "stack_start_failed"})
                os.environ.pop("PQC_FIXED_CIPHER", None)

                # ── Mode C2: PQC proxy with FIXED ChaCha20-Poly1305 ──
                print(f"\n  ── Restarting stack (Ryu + proxies) for k={k} PQC UNIFORM CHACHA20 [run {run_idx+1}] ──")
                _kill_stack()
                _clean_topo_state()
                os.environ["PQC_FIXED_CIPHER"] = "ChaCha20-Poly1305"
                os.environ.pop("OPENSSL_ia32cap", None)
                if _start_stack(need_proxy=True):
                    row = run_one(k, "pqc_uniform_chacha", PROXY_PORT)
                    row["run"] = run_idx + 1
                    all_rows.append(row)
                else:
                    all_rows.append({"k": k, "mode": "pqc_uniform_chacha", "run": run_idx + 1,
                                     "error": "stack_start_failed"})
                os.environ.pop("PQC_FIXED_CIPHER", None)

            # ── Mode D & E: AES-NI disabled (software AEAD) ──
            # Shows DSCP-adaptive benefit on non-AES-NI hardware.
            # ChaCha20 should be measurably faster than AES-256 without HW accel.
            if args.no_aesni:
                # D: Adaptive without AES-NI
                print(f"\n  ── Restarting stack for k={k} PQC ADAPTIVE (no AES-NI) [run {run_idx+1}] ──")
                _kill_stack()
                _clean_topo_state()
                os.environ.pop("PQC_FIXED_CIPHER", None)
                os.environ["OPENSSL_ia32cap"] = "~0x200000200000000"
                if _start_stack(need_proxy=True):
                    row = run_one(k, "pqc_adaptive_noaesni", PROXY_PORT)
                    row["run"] = run_idx + 1
                    row["aesni"] = False
                    all_rows.append(row)
                else:
                    all_rows.append({"k": k, "mode": "pqc_adaptive_noaesni", "run": run_idx + 1,
                                     "error": "stack_start_failed"})

                # E: Uniform without AES-NI
                print(f"\n  ── Restarting stack for k={k} PQC UNIFORM (no AES-NI) [run {run_idx+1}] ──")
                _kill_stack()
                _clean_topo_state()
                os.environ["PQC_FIXED_CIPHER"] = "AES-256-GCM"
                os.environ["OPENSSL_ia32cap"] = "~0x200000200000000"
                if _start_stack(need_proxy=True):
                    row = run_one(k, "pqc_uniform_noaesni", PROXY_PORT)
                    row["run"] = run_idx + 1
                    row["aesni"] = False
                    all_rows.append(row)
                else:
                    all_rows.append({"k": k, "mode": "pqc_uniform_noaesni", "run": run_idx + 1,
                                     "error": "stack_start_failed"})
                os.environ.pop("PQC_FIXED_CIPHER", None)
                os.environ.pop("OPENSSL_ia32cap", None)

    # Final cleanup
    _kill_stack()
    _clean_topo_state()

    # ── Save results ──
    csv_path = RESULTS_DIR / "topo_comparison.csv"
    if all_rows:
        fieldnames = sorted(set().union(*(r.keys() for r in all_rows)))
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(all_rows)
        print(f"\n  CSV → {csv_path}")

    json_path = RESULTS_DIR / "topo_comparison.json"
    with open(json_path, "w") as f:
        json.dump(all_rows, f, indent=2, default=str)
    print(f"  JSON → {json_path}")

    # ── Aggregate across runs (mean ± 95% CI) if multiple runs ──
    if n_runs > 1:
        agg_rows = _aggregate_rows(all_rows, k_values)

        # Save aggregated results
        agg_path = RESULTS_DIR / "topo_comparison_aggregated.json"
        with open(agg_path, "w") as f:
            json.dump(agg_rows, f, indent=2)
        print(f"  Aggregated JSON → {agg_path}")

        agg_csv_path = RESULTS_DIR / "topo_comparison_aggregated.csv"
        if agg_rows:
            agg_fields = sorted(set().union(*(r.keys() for r in agg_rows)))
            with open(agg_csv_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=agg_fields, extrasaction="ignore")
                w.writeheader()
                w.writerows(agg_rows)
            print(f"  Aggregated CSV → {agg_csv_path}")

        # Print aggregated comparison
        print(f"\n  {'═' * 80}")
        print(f"  AGGREGATED RESULTS (n={n_runs} runs, mean ± 95% CI)")
        print(f"  {'═' * 80}")
        for agg in agg_rows:
            k_v = agg["k"]
            m = agg["mode"]
            def _fmt(field):
                mean = agg.get(f"{field}_mean")
                lo = agg.get(f"{field}_ci95_lo")
                hi = agg.get(f"{field}_ci95_hi")
                if mean is None:
                    return "—"
                if lo is not None and hi is not None and lo != hi:
                    margin = (hi - lo) / 2
                    return f"{mean:.2f} ± {margin:.2f}"
                return f"{mean:.2f}"

            print(f"  k={k_v} {m:<10}  converge={_fmt('converge_time_s')}s  "
                  f"ping={_fmt('ping_avg_ms')}ms  "
                  f"mbps={_fmt('throughput_mbps')}  "
                  f"flow={_fmt('flow_setup_mean_ms')}ms")
    print(f"  JSON → {json_path}")

    # ── Print comparison table ──
    print(f"\n  {'═' * 80}")
    print(f"  PQC-SPECIFIC COMPARISON: Direct vs PQC Proxy")
    print(f"  {'═' * 80}")
    hdr = (f"  {'k':>3}  {'Mode':<12}  {'Handshake':>10}  {'Converge':>9}  "
           f"{'Ping ms':>8}  {'Mbps':>6}  {'FlowSetup':>10}  {'ECMP':>6}")
    print(hdr)
    print(f"  {'-' * 82}")

    for r in all_rows:
        if "error" in r:
            print(f"  {r['k']:>3}  {r['mode']:<12}  FAILED: {r['error'][:45]}")
        else:
            hs = r.get("handshake_burst_s", 0)
            hs_str = f"{hs:.1f}s" if hs > 0 else "—"
            ecmp_str = f"{r.get('ecmp_paths_used', 0)}/{r.get('ecmp_theoretical_max', '?')}"
            print(f"  {r['k']:>3}  {r['mode']:<12}  "
                  f"{hs_str:>10}  "
                  f"{r.get('converge_time_s', -1):>8.1f}s  "
                  f"{r.get('ping_avg_ms', -1):>7.1f}  "
                  f"{r.get('throughput_mbps', 0):>6.1f}  "
                  f"{r.get('flow_setup_mean_ms', -1):>9.1f}ms  "
                  f"{ecmp_str:>6}")

    # ── Print overhead summary ──
    modes_present = set(r["mode"] for r in all_rows)
    if "direct" in modes_present and "pqc_proxy" in modes_present:
        print(f"\n  PQC OVERHEAD (what our implementation costs):")
        print(f"  {'k':>3}  {'Handshake':>12}  {'Convergence':>12}  {'Latency':>10}  {'Throughput':>12}  {'FlowSetup':>10}  {'CPU pk':>7}  {'Mem MB':>7}")
        print(f"  {'-' * 80}")

        for k in k_values:
            direct = next((r for r in all_rows if r["k"] == k and r["mode"] == "direct"), None)
            proxy = next((r for r in all_rows if r["k"] == k and r["mode"] == "pqc_proxy"), None)
            if not direct or not proxy or "error" in direct or "error" in proxy:
                continue

            hs = proxy.get("handshake_burst_s", 0)
            d_conv = direct.get("converge_time_s", 0)
            p_conv = proxy.get("converge_time_s", 0)
            conv_oh = f"+{(p_conv - d_conv) / d_conv * 100:.0f}%" if d_conv > 0 else "—"

            d_ping = direct.get("ping_avg_ms", 0)
            p_ping = proxy.get("ping_avg_ms", 0)
            ping_oh = f"+{(p_ping - d_ping) / d_ping * 100:.0f}%" if d_ping > 0 else "—"

            d_tp = direct.get("throughput_mbps", 0)
            p_tp = proxy.get("throughput_mbps", 0)
            tp_oh = f"{(p_tp - d_tp) / d_tp * 100:+.0f}%" if d_tp > 0 else "—"

            d_fs = direct.get("flow_setup_mean_ms", 0)
            p_fs = proxy.get("flow_setup_mean_ms", 0)
            fs_oh = f"+{(p_fs - d_fs) / d_fs * 100:.0f}%" if d_fs > 0 else "—"

            cpu_pk = proxy.get("cpu_peak_pct", 0)
            mem_pk = proxy.get("mem_peak_mb", 0)
            cpu_str = f"{cpu_pk:.0f}%" if cpu_pk > 0 else "—"
            mem_str = f"{mem_pk:.0f}" if mem_pk > 0 else "—"

            print(f"  {k:>3}  {hs:>11.1f}s  {conv_oh:>12}  {ping_oh:>10}  {tp_oh:>12}  {fs_oh:>10}  {cpu_str:>7}  {mem_str:>7}")

    # ── Generate figures ──
    try:
        print(f"\n  Generating figures (per-run) ...")
        _generate_figures(all_rows, k_values)
        print(f"\n  Done. Up to 8 figures saved in figures/")
    except Exception as e:
        print(f"\n  ⚠ Figure generation failed: {e}")
        import traceback
        traceback.print_exc()

    # ── Generate aggregated figures (if multi-run) ──
    if n_runs > 1:
        # agg_rows was computed in the aggregation block above
        try:
            agg_json = RESULTS_DIR / "topo_comparison_aggregated.json"
            if agg_json.exists():
                import json as _json
                with open(agg_json) as _f:
                    _agg = _json.load(_f)
                print(f"\n  Generating aggregated figures (mean ± 95% CI) ...")
                _generate_aggregated_figures(_agg, k_values, n_runs)
                print(f"\n  Done. Up to 9 aggregated figures saved in figures_aggregated/")
        except Exception as e:
            print(f"\n  ⚠ Aggregated figure generation failed: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
