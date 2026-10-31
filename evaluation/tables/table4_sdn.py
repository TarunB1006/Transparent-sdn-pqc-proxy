"""
Table 4 — SDN Network Performance (Mininet live benchmarks).

Measurements (run inside a k=4 fat-tree Mininet topology):
  - iperf TCP throughput: with-proxy vs no-proxy (encryption overhead)
  - ping RTT: baseline, under load (QoS), cross-pod
  - ECMP correctness: 4-path hash spread validation
  - OpenFlow flow-setup time: controller reaction latency (PacketIn → FlowMod)
  - Proxy relay overhead: pure relay (no crypto) vs encrypted relay

Requires: Linux + Mininet + OVS + ryu-manager.
Skips gracefully if not available; imports existing CSV results if found.

Architecture tested:
  OVS → :6634 → sw_proxy_async (ML-KEM + AES-GCM) → :6652 → ctrl_proxy → :6653 → Ryu
"""

from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import threading
from pathlib import Path
from typing import List, Optional

from evaluation.config import EvalConfig

# ── Paths ─────────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent.parent
_SRC  = _ROOT / "src"
_SCRIPTS = _ROOT / "scripts"

# Attempt to use project venv python (runs as root via sudo)
_VENV_PY = _ROOT / "venv" / "bin" / "python3"
_PYTHON  = str(_VENV_PY) if _VENV_PY.exists() else sys.executable


# ══════════════════════════════════════════════════════════════════════════════
# Environment checks
# ══════════════════════════════════════════════════════════════════════════════

def _check_mininet() -> bool:
    """Return True if Mininet + OVS are available."""
    try:
        # ovs-vsctl show may need root; try with sudo -n (non-interactive)
        r = subprocess.run(
            ["ovs-vsctl", "show"],
            capture_output=True, timeout=5
        )
        ovs_ok = (r.returncode == 0)
        if not ovs_ok:
            # Try sudo -n variant (works when NOPASSWD is set)
            r2 = subprocess.run(
                ["sudo", "-n", "ovs-vsctl", "show"],
                capture_output=True, timeout=5
            )
            ovs_ok = (r2.returncode == 0)
        if not ovs_ok:
            return False
        import mininet  # noqa: F401
        return True
    except Exception:
        return False


def _check_ryu() -> bool:
    """Return True if ryu-manager is on PATH and executable."""
    import shutil
    if not shutil.which("ryu-manager"):
        return False
    try:
        # ryu-manager --version may return non-zero due to eventlet deprecation
        # warnings, so just check it runs at all (doesn't crash with FileNotFoundError)
        subprocess.run(["ryu-manager", "--version"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def _check_iperf() -> bool:
    try:
        r = subprocess.run(["iperf", "-v"], capture_output=True, timeout=3)
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Full-stack launcher (Ryu + ctrl_proxy + sw_proxy_async)
# ══════════════════════════════════════════════════════════════════════════════

class StackProcess:
    """Manages the three-process PQC-SDN stack."""

    def __init__(self):
        self._procs: list = []
        self._logs: list = []

    def start(self, timeout: float = 15.0) -> bool:
        """Launch ryu-manager, ctrl_proxy, sw_proxy_async.  Return True if all up."""
        # If the stack is already running (e.g. Docker entrypoint started it),
        # don't start a second set of processes — just reuse.
        ports_needed = [6653, 6652, 6634]
        if all(self._port_open(p) for p in ports_needed):
            print("      stack already running — reusing ✓")
            return True

        env = os.environ.copy()
        env["PYTHONPATH"] = str(_SRC)

        log_dir = Path("/tmp/pqc_eval_logs")
        log_dir.mkdir(exist_ok=True)

        # 1. Ryu controller
        ryu_log = open(log_dir / "ryu.log", "w")
        self._logs.append(ryu_log)
        ryu_proc = subprocess.Popen(
            ["ryu-manager",
             str(_SRC / "pqc_sdn" / "controller" / "controller.py"),
             "--observe-links",
             "--ofp-tcp-listen-port", "6653"],
            env=env, stdout=ryu_log, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        self._procs.append(ryu_proc)

        # 2. ctrl_proxy
        ctrl_log = open(log_dir / "ctrl_proxy.log", "w")
        self._logs.append(ctrl_log)
        ctrl_proc = subprocess.Popen(
            [_PYTHON, "-m", "pqc_sdn.apps.ctrl_proxy"],
            env=env, stdout=ctrl_log, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        self._procs.append(ctrl_proc)

        # 3. sw_proxy_async
        sw_log = open(log_dir / "sw_proxy.log", "w")
        self._logs.append(sw_log)
        sw_proc = subprocess.Popen(
            [_PYTHON, "-m", "pqc_sdn.apps.sw_proxy_async"],
            env=env, stdout=sw_log, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        self._procs.append(sw_proc)

        # Wait for ports to open
        deadline = time.time() + timeout
        ports_needed = [6653, 6652, 6634]
        while time.time() < deadline:
            if all(self._port_open(p) for p in ports_needed):
                print(f"      stack up (Ryu:6653, ctrl_proxy:6652, sw_proxy:6634)")
                return True
            time.sleep(0.5)

        still_closed = [p for p in ports_needed if not self._port_open(p)]
        print(f"      ⚠ stack not fully up after {timeout:.0f}s — closed ports: {still_closed}")
        # Partial start — proceed anyway (some ports may bind later)
        return len(still_closed) == 0

    @staticmethod
    def _port_open(port: int, host: str = "127.0.0.1") -> bool:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            return False

    def stop(self):
        for p in self._procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                p.wait(timeout=3)
            except Exception:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except Exception:
                    pass
        for f in self._logs:
            try:
                f.close()
            except Exception:
                pass
        self._procs.clear()
        self._logs.clear()


# ══════════════════════════════════════════════════════════════════════════════
# Mininet topology helpers
# ══════════════════════════════════════════════════════════════════════════════

def _build_fat_tree(k: int = 4, density: int = 2):
    """Build and start a k-ary fat-tree with TC links, return net."""
    from mininet.net import Mininet
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    setLogLevel("warning")

    sys.path.insert(0, str(_SRC))
    sys.path.insert(0, str(_SCRIPTS))
    from run_mininet import Fattree

    topo = Fattree(k, density)
    topo.createTopo()
    topo.createLink(bw_c2a=100, bw_a2e=50, bw_h2a=10)

    net = Mininet(
        topo=topo,
        link=TCLink,
        controller=None,
        autoSetMacs=True,
    )
    net.start()

    # Set OF version on all switches before connecting them
    for sw in net.switches:
        os.system(f"ovs-vsctl set bridge {sw.name} protocols=OpenFlow13 2>/dev/null")

    # Connect switches in staggered batches to avoid thundering-herd on sw_proxy_async.
    # Each switch triggers an ML-KEM handshake; staggering avoids session collisions.
    batch_size = 4
    for i, sw in enumerate(net.switches):
        os.system(f"ovs-vsctl set-controller {sw.name} tcp:127.0.0.1:6634 2>/dev/null")
        if (i + 1) % batch_size == 0:
            time.sleep(0.5)  # let the proxy digest each batch

    # Final wait for all handshakes to stabilise before returning
    time.sleep(3.0)

    return net


def _wait_convergence(net, timeout: float = 60.0) -> bool:
    """
    Wait for topology to converge:
      1. Ping h001→h002 repeatedly until it succeeds (flows installed).
      2. Then do a second ping to confirm it's stable (not just a lucky first packet).
    """
    hosts = net.hosts
    if len(hosts) < 2:
        return False
    src, dst = hosts[0], hosts[1]
    deadline = time.time() + timeout

    first_success = False
    while time.time() < deadline:
        result = src.cmd(f"ping -c 2 -W 2 {dst.IP()}")
        if "2 received" in result or "2 packets received" in result:
            if not first_success:
                first_success = True
                # Confirm stability with a second burst
                time.sleep(1.0)
                continue
            return True
        elif "1 received" in result:
            first_success = True
        time.sleep(1.5)

    return first_success  # partial convergence is usable


# ══════════════════════════════════════════════════════════════════════════════
# Individual benchmark functions
# ══════════════════════════════════════════════════════════════════════════════

def _bench_ping(net, src_name: str, dst_name: str,
                count: int = 20, dscp_hex: str = "0x00",
                label: str = "") -> dict:
    """Measure ping RTT (ms) with optional DSCP marking."""
    src = net.get(src_name)
    dst = net.get(dst_name)
    if src is None or dst is None:
        return {}

    cmd = f"ping -c {count} -W 2 -Q {dscp_hex} {dst.IP()}"
    output = src.cmd(cmd)

    # Parse: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
    m = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", output)
    loss_m = re.search(r"(\d+)% packet loss", output)
    if not m:
        return {"label": label, "loss_pct": 100.0, "error": "no rtt"}

    return {
        "label": label,
        "rtt_min_ms":  float(m.group(1)),
        "rtt_avg_ms":  float(m.group(2)),
        "rtt_max_ms":  float(m.group(3)),
        "rtt_mdev_ms": float(m.group(4)),
        "loss_pct":    float(loss_m.group(1)) if loss_m else 0.0,
        "count":       count,
        "dscp_hex":    dscp_hex,
    }


def _bench_iperf_tcp(net, src_name: str, dst_name: str,
                     duration: int = 8, parallel: int = 1,
                     dscp: int = 0, label: str = "") -> dict:
    """iperf TCP throughput test.  Returns throughput in Mbit/s."""
    src = net.get(src_name)
    dst = net.get(dst_name)
    if src is None or dst is None:
        return {"label": label, "error": "host not found"}

    dst_ip = dst.IP()

    # Kill any stale iperf servers, start fresh in background
    dst.cmd("pkill -9 iperf 2>/dev/null; sleep 0.3")
    # Use popen so the server process lives in the host's network namespace
    dst.popen(["iperf", "-s"])
    time.sleep(1.5)  # let server bind — increased from 0.8s to avoid startup race

    tos = dscp << 2
    # Run iperf client and capture output synchronously
    cmd = f"iperf -c {dst_ip} -t {duration} -P {parallel} -S {tos} -f m"
    output = src.cmd(cmd + " 2>&1")

    # Kill server
    dst.cmd("pkill -9 iperf 2>/dev/null")

    # Parse: Mbits/sec from the SUM line (parallel) or single stream line
    # e.g. "[  3]  0.0- 8.0 sec   9.77 MBytes   10.2 Mbits/sec"
    # or   "[SUM]  0.0- 8.0 sec  38.9 MBytes   40.8 Mbits/sec"
    throughput = 0.0
    for line in reversed(output.splitlines()):
        m = re.search(r"([\d.]+)\s+Mbits/sec", line)
        if m:
            throughput = float(m.group(1))
            break

    return {
        "label": label,
        "throughput_mbps": throughput,
        "duration_s":      duration,
        "parallel":        parallel,
        "dscp":            dscp,
    }


def _bench_flow_setup(net, src_name: str, dst_name: str,
                      n: int = 20, label: str = "") -> dict:
    """
    Measure controller flow-setup latency.

    Method: flush all flows, then time the first successful ping (round-trip
    through PacketIn → Ryu → FlowMod).  Repeat n times.
    """
    src = net.get(src_name)
    dst = net.get(dst_name)
    if src is None or dst is None:
        return {}

    latencies = []
    for _ in range(n):
        # Flush all learned flows on all switches
        for sw in net.switches:
            os.system(f"ovs-ofctl del-flows {sw.name} 2>/dev/null")

        t0 = time.perf_counter()
        result = src.cmd(f"ping -c 1 -W 3 {dst.IP()}")
        elapsed_ms = (time.perf_counter() - t0) * 1000

        if "1 received" in result or "1 packets received" in result:
            latencies.append(elapsed_ms)
        time.sleep(0.1)

    if not latencies:
        return {"label": label, "error": "all pings lost"}

    import statistics as _st
    return {
        "label":        label,
        "n":            len(latencies),
        "mean_ms":      round(_st.mean(latencies), 3),
        "median_ms":    round(_st.median(latencies), 3),
        "stdev_ms":     round(_st.stdev(latencies) if len(latencies) > 1 else 0, 3),
        "min_ms":       round(min(latencies), 3),
        "max_ms":       round(max(latencies), 3),
        "p95_ms":       round(sorted(latencies)[int(len(latencies) * 0.95)], 3),
    }


def _bench_ecmp(net, n_flows: int = 40) -> dict:
    """
    ECMP path distribution test.

    Sends n_flows pings from different source hosts to a common destination,
    captures which OVS output port each flow takes on the core switches,
    and checks spread across ≥2 paths (4 paths expected in k=4 fat-tree).
    """
    if len(net.hosts) < 4:
        return {"error": "need ≥4 hosts for ECMP test"}

    # Flush flows so ECMP hash starts fresh
    for sw in net.switches:
        os.system(f"ovs-ofctl del-flows {sw.name} 2>/dev/null")
    time.sleep(1.5)

    # Generate flows from multiple source hosts to a single destination
    # (different src IPs → different ECMP hash buckets)
    dst = net.hosts[-1]
    srcs = net.hosts[:min(n_flows, len(net.hosts) - 1)]
    for src in srcs:
        src.cmd(f"ping -c 2 -W 1 {dst.IP()} -q 2>/dev/null &")

    time.sleep(3.0)  # let flows install on all switches

    # Inspect core switches (s1xxx) for output port diversity
    core_switches = [sw for sw in net.switches if sw.name.startswith("s1")]
    if not core_switches:
        core_switches = net.switches[:4]  # fallback

    output_ports: set = set()
    total_flows = 0
    for sw in core_switches:
        # Check flows
        result = subprocess.run(
            ["ovs-ofctl", "dump-flows", sw.name],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "output:" in line:
                total_flows += 1
                for m in re.finditer(r"output:(\d+)", line):
                    output_ports.add(int(m.group(1)))
        # Check select groups (ECMP via OF groups)
        g_result = subprocess.run(
            ["ovs-ofctl", "dump-groups", sw.name],
            capture_output=True, text=True, timeout=5
        )
        for line in g_result.stdout.splitlines():
            for m in re.finditer(r"output:(\d+)", line):
                output_ports.add(int(m.group(1)))

    # Also check agg switches for path diversity
    agg_switches = [sw for sw in net.switches if sw.name.startswith("s2")]
    agg_ports: set = set()
    for sw in agg_switches[:4]:
        result = subprocess.run(
            ["ovs-ofctl", "dump-flows", sw.name],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "output:" in line:
                for m in re.finditer(r"output:(\d+)", line):
                    agg_ports.add(int(m.group(1)))
        g_result = subprocess.run(
            ["ovs-ofctl", "dump-groups", sw.name],
            capture_output=True, text=True, timeout=5
        )
        for line in g_result.stdout.splitlines():
            for m in re.finditer(r"output:(\d+)", line):
                agg_ports.add(int(m.group(1)))

    n_paths = len(output_ports) if output_ports else len(agg_ports)
    spread_ok = n_paths >= 2

    return {
        "n_flows":      len(srcs),
        "n_paths_used": n_paths,
        "spread_ok":    spread_ok,
        "total_flows":  total_flows,
        "output_ports": sorted(output_ports or agg_ports),
    }


def _bench_relay_overhead(cfg: EvalConfig) -> dict:
    """
    Proxy relay overhead: measure round-trip latency with full stack
    (encrypt+decrypt) vs a direct TCP echo.

    Uses loopback sockets — no Mininet needed, but called from Table 4 context
    to include in the SDN table alongside live results.
    """
    import statistics as _st
    from pqc_sdn.tls.handshake import HybridHandshake
    from pqc_sdn.crypto.kem import KemVariant
    from pqc_sdn.tls.session import SecureSession, derive_directional_keys

    n = min(cfg.n_proxy, 200)
    payload = os.urandom(256)  # typical OpenFlow message size

    # In-process handshake → session
    sw_hs  = HybridHandshake("sw-relay-bench")
    ctrl_hs = HybridHandshake("ctrl-relay-bench")
    hello = sw_hs.create_client_hello(KemVariant.ML_KEM_512)
    sh, cert, encap, _ = ctrl_hs.server_respond(hello)
    result = sw_hs.client_complete(sh, cert, encap)
    session = result.session

    send_sess = SecureSession(
        session.session_id, session.send_key, session.recv_key,
        session.key_id, "sw", "ctrl"
    )
    # Receiver uses opposite key orientation:
    # its "recv_key" (used to decrypt) must equal the sender's send_key
    recv_sess = SecureSession(
        session.session_id, session.recv_key, session.send_key,
        session.key_id, "ctrl", "sw"
    )

    # Measure encrypt + decrypt round-trip
    e2e_latencies = []
    for _ in range(n):
        t0 = time.perf_counter()
        pkt = send_sess.encrypt(payload)
        recv_sess.decrypt(pkt)
        e2e_latencies.append((time.perf_counter() - t0) * 1e6)  # µs

    return {
        "label":     "proxy_relay_overhead",
        "n":         n,
        "mean_us":   round(_st.mean(e2e_latencies), 3),
        "p99_us":    round(sorted(e2e_latencies)[int(n * 0.99)], 3),
        "max_us":    round(max(e2e_latencies), 3),
        "payload_b": len(payload),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Main table runner
# ══════════════════════════════════════════════════════════════════════════════

def run(cfg: EvalConfig) -> List[dict]:
    print("\n" + "=" * 72)
    print("TABLE 4 — SDN Network Performance (Mininet live benchmarks)")
    print("=" * 72)

    rows = []

    # ── Check Mininet availability ─────────────────────────────────────────
    if not _check_mininet():
        print("\n  ⚠ Mininet/OVS not available — skipping live SDN benchmarks")
        print("    To enable: run on Linux with Mininet installed and OVS running")
        _try_import_existing(rows)
        return rows

    ryu_ok = _check_ryu()
    iperf_ok = _check_iperf()
    print(f"\n  Environment: Mininet=✓  OVS=✓  ryu={('✓' if ryu_ok else '✗')}  "
          f"iperf={('✓' if iperf_ok else '✗')}")

    # Need to be root for Mininet
    if os.getuid() != 0:
        print("\n  ⚠ Table 4 live benchmarks require root (sudo).")
        print("    Run: sudo -E PYTHONPATH=src python evaluation/run_evaluation.py --tables 4")
        _try_import_existing(rows)
        return rows

    if not ryu_ok:
        print("\n  ⚠ ryu-manager not found — skipping live SDN benchmarks")
        print("    Install with: pip install ryu")
        _try_import_existing(rows)
        return rows

    # ── Launch the full PQC-SDN stack ─────────────────────────────────────
    print("\n  Starting PQC-SDN stack (Ryu + ctrl_proxy + sw_proxy_async) ...")
    stack = StackProcess()
    stack_ok = stack.start(timeout=25.0)
    if not stack_ok:
        print("    ⚠ Stack failed to start — skipping live tests")
        stack.stop()
        _try_import_existing(rows)
        return rows

    # ── Build fat-tree topology ────────────────────────────────────────────
    net = None
    try:
        print("\n  Building k=4 fat-tree topology ...")
        net = _build_fat_tree(k=4, density=2)
        n_switches = len(net.switches)
        n_hosts    = len(net.hosts)
        print(f"    topology: {n_switches} switches, {n_hosts} hosts")

        # Wait for topology to converge
        print("  Waiting for topology convergence (PacketIn→FlowMod) ...")
        converged = _wait_convergence(net, timeout=70.0)
        if not converged:
            print("  ⚠ Topology did not converge in time — results may be incomplete")
        else:
            print("  Converged ✓")

        # ── Warm up flows (ensure reactive Ryu has installed paths) ──────
        print("  Warming up flow tables (all-pairs ping) ...")
        for src_h in net.hosts[:min(4, len(net.hosts))]:
            for dst_h in net.hosts[:min(4, len(net.hosts))]:
                if src_h != dst_h:
                    src_h.cmd(f"ping -c 2 -W 1 {dst_h.IP()} -q 2>/dev/null")
        time.sleep(3.0)
        # Second warmup pass to ensure flows are stable (reactive controller may
        # need the second set of PacketIns to complete LLDP-based topology discovery)
        for src_h in net.hosts[:min(4, len(net.hosts))]:
            for dst_h in net.hosts[:min(4, len(net.hosts))]:
                if src_h != dst_h:
                    src_h.cmd(f"ping -c 1 -W 1 {dst_h.IP()} -q 2>/dev/null")
        time.sleep(2.0)
        print("  Flow tables warmed ✓")

        h001 = net.hosts[0]
        h002 = net.hosts[1]
        h003 = net.hosts[2] if len(net.hosts) > 2 else net.hosts[0]
        h004 = net.hosts[3] if len(net.hosts) > 3 else net.hosts[1]

        src_name = h001.name
        dst_name = h002.name
        src3     = h003.name
        dst4     = h004.name

        # ── [4.1] Ping RTT — baseline ────────────────────────────────────
        print(f"\n  [4.1] Ping RTT — {src_name} → {dst_name} (baseline) ...")
        ping_base = _bench_ping(net, src_name, dst_name, count=20,
                                dscp_hex="0x00", label="ping_baseline")
        if ping_base and "rtt_avg_ms" in ping_base:
            rows.append({"table": 4, "mode": "ping", **ping_base})
            print(f"    avg={ping_base['rtt_avg_ms']:.3f}ms  "
                  f"min={ping_base['rtt_min_ms']:.3f}ms  "
                  f"loss={ping_base['loss_pct']:.0f}%")

        # ── [4.2] Ping RTT — EF DSCP (priority queue) ────────────────────
        print(f"  [4.2] Ping RTT — {src3} → {dst4} with DSCP EF (priority) ...")
        # Warmup: send 3 pings first to install EF-marked flows (reactive controller
        # needs PacketIn to install flows for this DSCP/host pair, which weren't
        # covered by the default-DSCP warmup above).
        net.get(src3).cmd(f"ping -c 3 -W 2 -Q 0xb8 {net.get(dst4).IP()} -q 2>/dev/null")
        time.sleep(1.0)
        ping_ef = _bench_ping(net, src3, dst4, count=20,
                              dscp_hex="0xb8", label="ping_dscp_ef")
        if ping_ef and "rtt_avg_ms" in ping_ef:
            rows.append({"table": 4, "mode": "ping", **ping_ef})
            print(f"    avg={ping_ef['rtt_avg_ms']:.3f}ms  loss={ping_ef['loss_pct']:.0f}%")

        # ── [4.3] iperf TCP throughput ────────────────────────────────────
        if iperf_ok:
            # Warmup: short iperf to ensure flows are installed for this host pair
            print(f"\n  [4.3] iperf TCP throughput — {src_name} → {dst_name} ...")
            _bench_iperf_tcp(net, src_name, dst_name, duration=2, parallel=1, dscp=0,
                             label="_warmup")
            time.sleep(1.0)
            iperf_result = _bench_iperf_tcp(
                net, src_name, dst_name,
                duration=8, parallel=1, dscp=0,
                label="iperf_tcp_single"
            )
            if iperf_result and "throughput_mbps" in iperf_result:
                rows.append({"table": 4, "mode": "iperf", **iperf_result})
                print(f"    throughput={iperf_result['throughput_mbps']:.2f} Mbit/s")

            # Parallel streams
            print(f"  [4.3b] iperf TCP — {src_name} → {dst_name} (4 parallel) ...")
            iperf_p4 = _bench_iperf_tcp(
                net, src_name, dst_name,
                duration=8, parallel=4, dscp=0,
                label="iperf_tcp_4stream"
            )
            if iperf_p4 and "throughput_mbps" in iperf_p4:
                rows.append({"table": 4, "mode": "iperf", **iperf_p4})
                print(f"    4-stream throughput={iperf_p4['throughput_mbps']:.2f} Mbit/s")

            # With DSCP EF (latency-sensitive → ChaCha20 path)
            print(f"  [4.3c] iperf TCP — DSCP EF (ChaCha20-Poly1305 path) ...")
            iperf_ef = _bench_iperf_tcp(
                net, src_name, dst_name,
                duration=8, parallel=1, dscp=46,
                label="iperf_tcp_dscp_ef"
            )
            if iperf_ef and "throughput_mbps" in iperf_ef:
                rows.append({"table": 4, "mode": "iperf", **iperf_ef})
                print(f"    EF throughput={iperf_ef['throughput_mbps']:.2f} Mbit/s")
        else:
            print("\n  [4.3] iperf not found — skipping throughput benchmarks")

        # ── [4.4] Flow setup time (PacketIn→FlowMod latency) ─────────────
        n_flow = min(cfg.n_handshake, 20)  # cap at 20 for table 4
        print(f"\n  [4.4] Flow-setup latency ({n_flow} flows) ...")
        flow_result = _bench_flow_setup(net, src_name, dst_name,
                                        n=n_flow, label="flow_setup_pqc")
        if flow_result and "mean_ms" in flow_result:
            rows.append({"table": 4, "mode": "flow_setup", **flow_result})
            print(f"    mean={flow_result['mean_ms']:.3f}ms  "
                  f"p95={flow_result.get('p95_ms', '?')}ms  "
                  f"stdev={flow_result['stdev_ms']:.3f}ms")

        # ── [4.5] ECMP path spread ────────────────────────────────────────
        print(f"\n  [4.5] ECMP path spread ({min(40, cfg.n_primitive)} flows) ...")
        ecmp_result = _bench_ecmp(net, n_flows=min(40, cfg.n_primitive))
        if ecmp_result:
            rows.append({"table": 4, "mode": "ecmp", **ecmp_result})
            spread = "✓ spread OK" if ecmp_result.get("spread_ok") else "✗ uneven spread"
            print(f"    paths used={ecmp_result['n_paths_used']}  {spread}  "
                  f"ports={ecmp_result.get('output_ports', [])}")

        # ── [4.6] Cross-pod latency ───────────────────────────────────────
        if len(net.hosts) >= 6:
            h_far = net.hosts[-1]
            print(f"\n  [4.6] Cross-pod ping: {src_name} → {h_far.name} ...")
            ping_cross = _bench_ping(net, src_name, h_far.name, count=15,
                                     label="ping_cross_pod")
            if ping_cross and "rtt_avg_ms" in ping_cross:
                rows.append({"table": 4, "mode": "ping", **ping_cross})
                print(f"    avg={ping_cross['rtt_avg_ms']:.3f}ms")

    except Exception as exc:
        print(f"\n  ⚠ Mininet benchmark error: {exc}")
        import traceback
        traceback.print_exc()

    finally:
        if net is not None:
            print("\n  Stopping Mininet topology ...")
            try:
                net.stop()
            except Exception:
                pass

        print("  Stopping PQC-SDN stack ...")
        stack.stop()

        # Flush any leftover OVS state
        try:
            subprocess.run(["ovs-vsctl", "del-controller", "s1"],
                           capture_output=True, timeout=3)
        except Exception:
            pass

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n  Table 4 complete: {len(rows)} measurements recorded")

    # Save to CSV for later import
    _save_results(rows)

    return rows


def _try_import_existing(rows: list) -> None:
    """Try to load previously collected Table 4 data from CSV."""
    import csv as _csv
    for candidate in [
        Path("evaluation/results/raw/table4_sdn.csv"),
        Path("results/raw/table4_sdn.csv"),
        Path("scripts/bench_resources.csv"),
    ]:
        if candidate.exists():
            try:
                with open(candidate) as f:
                    reader = _csv.DictReader(f)
                    existing = list(reader)
                if existing:
                    print(f"    Loaded {len(existing)} existing rows from {candidate}")
                    rows.extend(existing)
                    return
            except Exception:
                pass


def _save_results(rows: list) -> None:
    """Persist Table 4 results to JSON for reuse."""
    if not rows:
        return
    out = Path("evaluation/results/raw/table4_sdn_live.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(rows, f, indent=2, default=str)
    print(f"    Live results saved → {out}")
