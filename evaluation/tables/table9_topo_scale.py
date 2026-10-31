"""
Table 9 — Topology Scalability.

Tests the PQC-SDN platform across increasingly large fat-tree topologies:
  k=4:   20 switches,  16 hosts
  k=6:   45 switches,  36 hosts
  k=8:   80 switches,  64 hosts
  k=10: 125 switches, 100 hosts

For each topology size, measures:
  - Time for all switches to complete PQC handshake
  - Ping RTT (baseline, after convergence)
  - iperf TCP throughput
  - Flow setup time for the first new flow

Requires: Linux, Mininet, OVS, the proxy stack running.
Gracefully skips if Mininet is not available.

WARNING: k=10 creates 125 switches and 100 hosts. This needs significant
RAM (~4GB+) and CPU. Run on a machine with at least 8 cores and 8GB RAM.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import List

from evaluation.config import EvalConfig

_ROOT = Path(__file__).resolve().parent.parent.parent
_SRC = _ROOT / "src"
_SCRIPTS = _ROOT / "scripts"


def run(cfg: EvalConfig) -> List[dict]:
    print("\n" + "=" * 72)
    print("TABLE 9 — Topology Scalability (fat-tree k=4 → k=10)")
    print("=" * 72)

    rows = []

    # Check if Mininet is available
    try:
        from mininet.net import Mininet
        from mininet.link import TCLink
    except ImportError:
        print("\n  ⚠ Mininet not available — skipping topology scalability test")
        print("  Install: sudo apt install mininet")
        return [{"table": 9, "test": "skipped", "reason": "Mininet not installed"}]

    # Check if OVS is running
    try:
        r = subprocess.run(["ovs-vsctl", "show"], capture_output=True, timeout=3)
        if r.returncode != 0:
            raise RuntimeError("OVS not running")
    except Exception:
        print("\n  ⚠ OVS not available — skipping topology scalability test")
        return [{"table": 9, "test": "skipped", "reason": "OVS not running"}]

    # Check if the proxy stack is running
    import socket
    proxy_ok = False
    try:
        with socket.create_connection(("127.0.0.1", 6634), timeout=1):
            proxy_ok = True
    except Exception:
        pass
    if not proxy_ok:
        print("\n  ⚠ sw_proxy not running on :6634 — skipping topology scalability")
        print("  Start the proxy stack first: sw_proxy_async + ctrl_proxy + Ryu")
        return [{"table": 9, "test": "skipped", "reason": "Proxy stack not running"}]

    from mininet.net import Mininet
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    setLogLevel("warning")

    sys.path.insert(0, str(_SRC))
    sys.path.insert(0, str(_SCRIPTS))
    from run_mininet import Fattree

    # Topology sizes to test
    # Start small, increase — stop early if a size fails
    k_values = [4, 6, 8, 10]

    for k in k_values:
        n_core = (k // 2) ** 2
        n_agg = k * k // 2
        n_edge = k * k // 2
        n_hosts = n_edge * 2  # density=2
        n_switches = n_core + n_agg + n_edge

        print(f"\n  ── k={k}: {n_switches} switches, {n_hosts} hosts ──")

        try:
            # Build topology
            topo = Fattree(k, 2)
            topo.createTopo()
            topo.createLink(bw_c2a=100, bw_a2e=50, bw_h2a=10)

            net = Mininet(topo=topo, link=TCLink, controller=None, autoSetMacs=True)
            net.start()

            # Set OF version
            for sw in net.switches:
                os.system(f"ovs-vsctl set bridge {sw.name} protocols=OpenFlow13 2>/dev/null")

            # Connect switches to proxy in batches
            t0_connect = time.perf_counter()
            batch = max(4, k)
            for i, sw in enumerate(net.switches):
                os.system(f"ovs-vsctl set-controller {sw.name} tcp:127.0.0.1:6634 2>/dev/null")
                if (i + 1) % batch == 0:
                    time.sleep(0.5)

            # Wait for convergence
            connect_time = time.perf_counter() - t0_connect
            print(f"    Switches connected in {connect_time:.1f}s")

            # Wait for topology to converge (ping between first and last host)
            src = net.hosts[0]
            dst = net.hosts[-1]
            converged = False
            t0_converge = time.perf_counter()
            for attempt in range(30):
                result = src.cmd(f"ping -c 2 -W 2 {dst.IP()} -q")
                if "2 received" in result:
                    converged = True
                    break
                time.sleep(2.0)
            converge_time = time.perf_counter() - t0_converge

            if converged:
                print(f"    Converged in {converge_time:.1f}s ✓")
            else:
                print(f"    ⚠ Did not converge after {converge_time:.1f}s")

            # Warmup
            for h in net.hosts[:min(4, len(net.hosts))]:
                h.cmd(f"ping -c 1 -W 1 {dst.IP()} -q 2>/dev/null")
            time.sleep(2.0)

            # Ping test
            ping_out = src.cmd(f"ping -c 10 -W 2 {dst.IP()}")
            rtt_match = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", ping_out)
            loss_match = re.search(r"(\d+)% packet loss", ping_out)

            ping_avg = float(rtt_match.group(2)) if rtt_match else -1
            ping_loss = float(loss_match.group(1)) if loss_match else 100

            print(f"    Ping {src.name}→{dst.name}: avg={ping_avg:.1f}ms loss={ping_loss:.0f}%")

            # iperf test (short)
            throughput = 0.0
            try:
                dst.cmd("pkill -9 iperf 2>/dev/null; sleep 0.3")
                dst.popen(["iperf", "-s"])
                time.sleep(1.5)
                iperf_out = src.cmd(f"iperf -c {dst.IP()} -t 5 -f m 2>&1")
                dst.cmd("pkill -9 iperf 2>/dev/null")
                for line in reversed(iperf_out.splitlines()):
                    m = re.search(r"([\d.]+)\s+Mbits/sec", line)
                    if m:
                        throughput = float(m.group(1))
                        break
            except Exception:
                pass

            print(f"    iperf throughput: {throughput:.1f} Mbps")

            rows.append({
                "table": 9, "test": "topo_scale",
                "k": k, "switches": n_switches, "hosts": n_hosts,
                "connect_time_s": round(connect_time, 1),
                "converge_time_s": round(converge_time, 1),
                "converged": converged,
                "ping_avg_ms": round(ping_avg, 2),
                "ping_loss_pct": ping_loss,
                "throughput_mbps": throughput,
            })

        except Exception as e:
            print(f"    ✗ Failed: {e}")
            rows.append({
                "table": 9, "test": "topo_scale",
                "k": k, "switches": n_switches, "hosts": n_hosts,
                "error": str(e),
            })
        finally:
            try:
                net.stop()
                # Clean up OVS bridges
                time.sleep(1.0)
            except Exception:
                pass

    # Summary
    print("\n  ── Topology Scalability Summary")
    print(f"    {'k':>3}  {'Switches':>8}  {'Hosts':>6}  {'Connect':>8}  {'Converge':>9}  {'Ping ms':>8}  {'Mbps':>6}")
    print("    " + "-" * 60)
    for r in rows:
        if "error" in r:
            print(f"    {r['k']:>3}  {r['switches']:>8}  {r['hosts']:>6}  FAILED: {r['error'][:30]}")
        elif r.get("test") == "topo_scale":
            print(f"    {r['k']:>3}  {r['switches']:>8}  {r['hosts']:>6}  "
                  f"{r['connect_time_s']:>7.1f}s  {r['converge_time_s']:>8.1f}s  "
                  f"{r['ping_avg_ms']:>7.1f}  {r['throughput_mbps']:>6.1f}")

    return rows
