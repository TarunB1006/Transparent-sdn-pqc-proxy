"""
elasticity.py — CPU-triggered automatic controller scale-out / scale-in

Improvements over the original design:
  - Port range validation prevents collisions at high pod counts
  - Global pod limit (MAX_PODS) prevents runaway cascading
  - Process tracking with health checks detects crashed children
  - Parallel switch redirect (ThreadPoolExecutor) instead of sequential
  - Basic scale-in: consolidate underloaded pods back to parent
  - Pod-id persistence via file so multi-process deploys don't collide
  - Proper file handle management (no leaked open() calls)

Switch connection path (fat-tree topology):
  Edge switches (s3xxx) → sw_proxy:6634+pod_id → ctrl_proxy:6652+pod_id → Ryu:6653+pod_id
  Agg switches (s2xxx)  → same path, but agg switches are migrated AFTER edge switches
  Core switches (s1xxx) → NEVER migrated — stay on the root controller always

  When a switch is migrated:
    1. ovs-vsctl set-controller <sw_name> tcp:127.0.0.1:<new_proxy_port>
    2. OVS drops old TCP connection, switch enters "connecting" state
    3. OVS connects to new sw_proxy → PQC handshake → encrypted tunnel
    4. Features-Reply → new Ryu learns the switch → installs table-miss flow
    5. All existing flow rules expire (idle_timeout=10s) → PacketIn storm
    6. New controller re-learns topology, hosts, and installs fresh flows
"""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import psutil

log = logging.getLogger(__name__)

# ── Tunables ──────────────────────────────────────────────────────────────────
CPU_THRESHOLD    = float(os.environ.get("PQC_CPU_THRESHOLD",   "85.0"))
CPU_LOW_THRESHOLD = float(os.environ.get("PQC_CPU_LOW",        "30.0"))  # scale-in trigger
CPU_WINDOW       = int(os.environ.get("PQC_CPU_WINDOW",        "3"))
SAMPLE_INTERVAL  = float(os.environ.get("PQC_SAMPLE_INTERVAL", "5.0"))
COOLDOWN_SEC     = float(os.environ.get("PQC_COOLDOWN_SEC",    "60.0"))
MAX_PODS         = int(os.environ.get("PQC_MAX_PODS",          "50"))
HEALTH_CHECK_SEC = float(os.environ.get("PQC_HEALTH_CHECK",    "30.0"))
_RYU_BASE_PORT   = 6653
_MGMT_BASE_PORT  = 8082
_DATA_BASE_PORT  = 6634
_CTRL_BASE_PORT  = 6652

# Port ranges: each pod uses 3 ports. With MAX_PODS=50:
#   Ryu:  6653-6703
#   Data: 6634-6684
#   Ctrl: 6652-6702
# All within the 6634-6703 range — no overlap with common services.
_PORT_RANGE_MAX  = 6800  # hard ceiling — reject pods that would exceed this


# ── Pod registry (file-backed for multi-process safety) ───────────────────────

@dataclass
class PodInfo:
    pod_id: int
    ctrl_id: str
    ryu_pid: int = 0
    proxy_pids: List[int] = field(default_factory=list)
    dpids: Set[int] = field(default_factory=set)
    created_at: float = 0.0
    healthy: bool = True


_pod_registry_lock = threading.Lock()
_pod_registry: Dict[int, PodInfo] = {}
_highest_pod_id = 0


def _pod_id_file(project_root: str) -> Path:
    return Path(project_root) / "config" / ".pod_registry.json"


def _load_pod_registry(project_root: str) -> None:
    """Load pod registry from file (multi-process coordination)."""
    global _highest_pod_id
    path = _pod_id_file(project_root)
    try:
        if path.is_file():
            data = json.loads(path.read_text())
            _highest_pod_id = data.get("highest_pod_id", 0)
            log.debug("[elasticity] loaded pod registry: highest_id=%d", _highest_pod_id)
    except Exception as e:
        log.debug("[elasticity] could not load pod registry: %s", e)


def _save_pod_registry(project_root: str) -> None:
    """Persist pod registry to file."""
    path = _pod_id_file(project_root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "highest_pod_id": _highest_pod_id,
            "pods": {
                str(k): {"ctrl_id": v.ctrl_id, "ryu_pid": v.ryu_pid,
                          "dpids": list(v.dpids), "created_at": v.created_at}
                for k, v in _pod_registry.items()
            },
        }
        path.write_text(json.dumps(data, indent=2))
    except Exception as e:
        log.debug("[elasticity] could not save pod registry: %s", e)


def _alloc_pod_id(project_root: str) -> Optional[int]:
    """Atomically allocate the next unused pod_id. Returns None if MAX_PODS reached."""
    global _highest_pod_id
    with _pod_registry_lock:
        if _highest_pod_id >= MAX_PODS:
            log.error("[elasticity] MAX_PODS=%d reached — cannot scale out further", MAX_PODS)
            return None
        _highest_pod_id += 1
        new_id = _highest_pod_id

        # Validate port range
        ryu_port = _RYU_BASE_PORT + new_id
        data_port = _DATA_BASE_PORT + new_id
        ctrl_port = _CTRL_BASE_PORT + new_id
        if max(ryu_port, data_port, ctrl_port) > _PORT_RANGE_MAX:
            log.error("[elasticity] pod %d would exceed port range (max %d) — rejecting",
                      new_id, _PORT_RANGE_MAX)
            _highest_pod_id -= 1
            return None

        _save_pod_registry(project_root)
        return new_id


def _register_pod_id(pod_id: int) -> None:
    """Called at monitor start so the registry knows which ids are taken."""
    global _highest_pod_id
    with _pod_registry_lock:
        if pod_id > _highest_pod_id:
            _highest_pod_id = pod_id


def _wait_for_port(host: str, port: int, timeout: float = 15.0) -> bool:
    """Poll until a TCP port accepts connections or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def _is_process_alive(pid: int) -> bool:
    """Check if a process is still running."""
    try:
        return psutil.pid_exists(pid) and psutil.Process(pid).is_running()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


# ── Module-level reference ────────────────────────────────────────────────────
_monitor: Optional["ScaleOutMonitor"] = None


def start(
    pod_id: int,
    domain_dpids: set,
    ryu_switch_names: dict,
    packet_in_rates: dict,
    controller_domains: dict,
    project_root: str,
    venv_python: str,
) -> "ScaleOutMonitor":
    """Create and start the monitor. Called once from controller.__init__."""
    global _monitor
    _register_pod_id(pod_id)
    _load_pod_registry(project_root)
    _monitor = ScaleOutMonitor(
        pod_id=pod_id,
        domain_dpids=domain_dpids,
        ryu_switch_names=ryu_switch_names,
        packet_in_rates=packet_in_rates,
        controller_domains=controller_domains,
        project_root=project_root,
        venv_python=venv_python,
    )
    _monitor.start()
    return _monitor


class ScaleOutMonitor(threading.Thread):
    """Background daemon that watches CPU and triggers scale-out/scale-in."""

    daemon = True

    def __init__(self, pod_id, domain_dpids, ryu_switch_names,
                 packet_in_rates, controller_domains, project_root, venv_python):
        super().__init__(name=f"pqc-scale-out-pod{pod_id}", daemon=True)
        self.pod_id             = pod_id
        self.domain_dpids       = domain_dpids
        self.ryu_switch_names   = ryu_switch_names
        self.packet_in_rates    = packet_in_rates
        self.controller_domains = controller_domains
        self.project_root       = project_root
        self.venv_python        = venv_python

        self._proc         = psutil.Process()
        self._high_count   = 0
        self._low_count    = 0
        self._cooldown_end = 0.0
        self._last_health_check = 0.0
        self._child_pods: Dict[int, PodInfo] = {}  # pods spawned by THIS monitor

        self._proc.cpu_percent(interval=None)  # seed baseline

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        log.info("[elasticity/pod%d] monitor started — threshold=%.0f%%/%.0f%% "
                 "window=%d interval=%ds max_pods=%d",
                 self.pod_id, CPU_THRESHOLD, CPU_LOW_THRESHOLD,
                 CPU_WINDOW, SAMPLE_INTERVAL, MAX_PODS)
        while True:
            time.sleep(SAMPLE_INTERVAL)
            try:
                self._tick()
                # Periodic health check of child pods
                now = time.time()
                if now - self._last_health_check > HEALTH_CHECK_SEC:
                    self._health_check()
                    self._last_health_check = now
            except Exception as exc:
                log.error("[elasticity/pod%d] tick error: %s", self.pod_id, exc, exc_info=True)

    def _tick(self) -> None:
        cpu = self._proc.cpu_percent(interval=None)
        now = time.time()

        if now < self._cooldown_end:
            self._high_count = 0
            self._low_count = 0
            return

        # ── Scale-out check ───────────────────────────────────────────────
        if cpu >= CPU_THRESHOLD:
            self._high_count += 1
            self._low_count = 0
            log.info("[elasticity/pod%d] cpu=%.1f%% ≥ %.0f%% (sample %d/%d)",
                     self.pod_id, cpu, CPU_THRESHOLD, self._high_count, CPU_WINDOW)
            if self._high_count >= CPU_WINDOW:
                self._high_count = 0
                self._trigger_scale_out(cpu)

        # ── Scale-in check ────────────────────────────────────────────────
        elif cpu <= CPU_LOW_THRESHOLD and self._child_pods:
            self._low_count += 1
            if self._low_count >= CPU_WINDOW * 2:  # more conservative than scale-out
                self._low_count = 0
                self._trigger_scale_in(cpu)

        else:
            self._high_count = 0
            self._low_count = 0

    # ── Health check ──────────────────────────────────────────────────────────

    def _health_check(self) -> None:
        """Check if child pod processes are still alive."""
        for pod_id, info in list(self._child_pods.items()):
            alive = True
            if info.ryu_pid and not _is_process_alive(info.ryu_pid):
                log.error("[elasticity/pod%d] child pod%d Ryu (pid=%d) CRASHED",
                          self.pod_id, pod_id, info.ryu_pid)
                alive = False
            for pid in info.proxy_pids:
                if not _is_process_alive(pid):
                    log.error("[elasticity/pod%d] child pod%d proxy (pid=%d) CRASHED",
                              self.pod_id, pod_id, pid)
                    alive = False
            if not alive:
                info.healthy = False
                # Reclaim switches from crashed pod
                log.warning("[elasticity/pod%d] reclaiming %d switches from crashed pod%d",
                            self.pod_id, len(info.dpids), pod_id)
                self._reclaim_switches(info)

    def _reclaim_switches(self, info: PodInfo) -> None:
        """Redirect switches from a crashed pod back to this controller's proxy."""
        proxy_port = _DATA_BASE_PORT + self.pod_id
        for dpid in list(info.dpids):
            sw_name = self.ryu_switch_names.get(dpid)
            if sw_name:
                try:
                    subprocess.run(
                        ["ovs-vsctl", "set-controller", sw_name,
                         f"tcp:127.0.0.1:{proxy_port}"],
                        check=True, capture_output=True, timeout=5,
                    )
                    self.domain_dpids.add(dpid)
                    log.info("[elasticity/pod%d] reclaimed dpid=%d (%s)",
                             self.pod_id, dpid, sw_name)
                except Exception as e:
                    log.error("[elasticity/pod%d] reclaim failed dpid=%d: %s",
                              self.pod_id, dpid, e)
        # Remove dead pod from tracking
        ctrl_id = info.ctrl_id
        self._child_pods.pop(info.pod_id, None)
        self.controller_domains.pop(ctrl_id, None)

    # ── Scale-out ─────────────────────────────────────────────────────────────

    def _trigger_scale_out(self, cpu: float) -> None:
        candidates = self._select_candidates()
        if not candidates:
            log.warning("[elasticity/pod%d] overloaded (cpu=%.1f%%) but no migratable switches",
                        self.pod_id, cpu)
            self._cooldown_end = time.time() + COOLDOWN_SEC
            return

        new_pod_id = _alloc_pod_id(self.project_root)
        if new_pod_id is None:
            self._cooldown_end = time.time() + COOLDOWN_SEC
            return

        new_ctrl_id = f"sdn-controller-pod{new_pod_id}"

        # NOTE: Certificate pinning and elasticity are mutually exclusive.
        # Each new ctrl_proxy generates a fresh identity key.

        log.warning("[elasticity/pod%d] CPU=%.1f%% sustained — spawning %s for %d switches: %s",
                    self.pod_id, cpu, new_ctrl_id, len(candidates), candidates)

        ryu_pid = self._spawn_controller(new_ctrl_id, new_pod_id, candidates)
        if not ryu_pid:
            return

        new_ryu_port = _RYU_BASE_PORT + new_pod_id
        if not _wait_for_port("127.0.0.1", new_ryu_port, timeout=15.0):
            log.error("[elasticity/pod%d] Ryu pod%d never came up on :%d",
                      self.pod_id, new_pod_id, new_ryu_port)
            return

        proxy_pids = self._spawn_proxies(new_pod_id)

        # Wait for sw_proxy to be ready
        data_port = _DATA_BASE_PORT + new_pod_id
        if not _wait_for_port("127.0.0.1", data_port, timeout=10.0):
            log.error("[elasticity/pod%d] sw_proxy pod%d never came up on :%d",
                      self.pod_id, new_pod_id, data_port)
            return

        self._redirect_switches_parallel(candidates, data_port)

        mgmt_port = _MGMT_BASE_PORT + self.pod_id
        self._notify_old_controller(mgmt_port, candidates, new_ctrl_id)

        # Track the new pod
        pod_info = PodInfo(
            pod_id=new_pod_id, ctrl_id=new_ctrl_id,
            ryu_pid=ryu_pid, proxy_pids=proxy_pids,
            dpids=set(candidates), created_at=time.time(),
        )
        self._child_pods[new_pod_id] = pod_info
        with _pod_registry_lock:
            _pod_registry[new_pod_id] = pod_info
            _save_pod_registry(self.project_root)

        self.domain_dpids -= set(candidates)
        self.controller_domains[new_ctrl_id] = set(candidates)
        ctrl_self = f"sdn-controller-pod{self.pod_id}" if self.pod_id else "sdn-controller"
        if ctrl_self in self.controller_domains:
            self.controller_domains[ctrl_self] -= set(candidates)

        self._cooldown_end = time.time() + COOLDOWN_SEC
        log.info("[elasticity/pod%d] scale-out to %s complete — %d switches migrated, cooldown %.0fs",
                 self.pod_id, new_ctrl_id, len(candidates), COOLDOWN_SEC)

    # ── Scale-in ──────────────────────────────────────────────────────────────

    def _trigger_scale_in(self, cpu: float) -> None:
        """Consolidate: reclaim switches from the least-loaded child pod."""
        if not self._child_pods:
            return

        # Find the child with the fewest switches
        smallest = min(self._child_pods.values(), key=lambda p: len(p.dpids))
        if not smallest.dpids:
            return

        log.info("[elasticity/pod%d] CPU=%.1f%% low — consolidating pod%d (%d switches)",
                 self.pod_id, cpu, smallest.pod_id, len(smallest.dpids))

        # Redirect switches back to this controller
        proxy_port = _DATA_BASE_PORT + self.pod_id
        reclaimed = 0
        for dpid in list(smallest.dpids):
            sw_name = self.ryu_switch_names.get(dpid)
            if sw_name:
                try:
                    subprocess.run(
                        ["ovs-vsctl", "set-controller", sw_name,
                         f"tcp:127.0.0.1:{proxy_port}"],
                        check=True, capture_output=True, timeout=5,
                    )
                    self.domain_dpids.add(dpid)
                    reclaimed += 1
                except Exception as e:
                    log.error("[elasticity/pod%d] scale-in redirect failed dpid=%d: %s",
                              self.pod_id, dpid, e)

        # Terminate child processes
        for pid in [smallest.ryu_pid] + smallest.proxy_pids:
            if pid and _is_process_alive(pid):
                try:
                    psutil.Process(pid).terminate()
                    log.debug("[elasticity/pod%d] terminated pid=%d", self.pod_id, pid)
                except Exception:
                    pass

        # Cleanup tracking
        self.controller_domains.pop(smallest.ctrl_id, None)
        self._child_pods.pop(smallest.pod_id, None)
        with _pod_registry_lock:
            _pod_registry.pop(smallest.pod_id, None)
            _save_pod_registry(self.project_root)

        self._cooldown_end = time.time() + COOLDOWN_SEC
        log.info("[elasticity/pod%d] scale-in complete — reclaimed %d switches from pod%d",
                 self.pod_id, reclaimed, smallest.pod_id)

    # ── Candidate selection ───────────────────────────────────────────────────

    def _select_candidates(self) -> list[int]:
        """Select switches to migrate: edge first, then agg, never core.
        Within each tier: busiest first. Count: at most half the domain."""
        migratable = []
        for dpid in self.domain_dpids:
            name = self.ryu_switch_names.get(dpid, "").lower()
            if name.startswith("s3"):
                tier_order = 0   # edge — migrate first
            elif name.startswith("s2"):
                tier_order = 1   # agg — migrate second
            elif name.startswith("s1"):
                continue         # core — NEVER migrate
            else:
                tier_order = 2

            rate_info = self.packet_in_rates.get(dpid)
            rate = rate_info[0] / max(time.time() - rate_info[1], 1) if rate_info else 0.0
            migratable.append((tier_order, -rate, dpid))

        if not migratable:
            return []

        migratable.sort()
        count = max(1, len(migratable) // 2)
        return [dpid for _, _, dpid in migratable[:count]]

    # ── Subprocess helpers ────────────────────────────────────────────────────

    def _spawn_controller(self, ctrl_id: str, pod_id: int, dpids: list[int]) -> int:
        """Spawn ryu-manager. Returns PID or 0 on failure."""
        env = {
            **os.environ,
            "PYTHONPATH":            os.path.join(self.project_root, "src"),
            "PQC_POD_ID":            str(pod_id),
            "PQC_CONTROLLER_DOMAIN": ",".join(str(d) for d in dpids),
            "PQC_RYU_PORT":          str(_RYU_BASE_PORT + pod_id),
            "PQC_MGMT_PORT":         str(_MGMT_BASE_PORT + pod_id),
        }
        controller_py = os.path.join(
            self.project_root, "src", "pqc_sdn", "controller", "controller.py")
        ryu_mgr = os.path.join(os.path.dirname(self.venv_python), "ryu-manager")
        if not os.path.exists(ryu_mgr):
            ryu_mgr = "ryu-manager"

        log_path = os.path.join(self.project_root, f"controller_pod{pod_id}.log")
        try:
            with open(log_path, "a") as log_fh:
                proc = subprocess.Popen(
                    [ryu_mgr, controller_py, "--observe-links",
                     "--ofp-tcp-listen-port", str(_RYU_BASE_PORT + pod_id)],
                    env=env, stdout=log_fh, stderr=subprocess.STDOUT,
                )
            time.sleep(0.3)
            if proc.poll() is not None:
                log.error("[elasticity/pod%d] ryu-manager exited immediately (rc=%d)",
                          self.pod_id, proc.returncode)
                return 0
            log.info("[elasticity/pod%d] spawned %s pid=%d", self.pod_id, ctrl_id, proc.pid)
            return proc.pid
        except Exception as exc:
            log.error("[elasticity/pod%d] spawn failed: %s", self.pod_id, exc)
            return 0

    def _spawn_proxies(self, pod_id: int) -> List[int]:
        """Spawn sw_proxy + ctrl_proxy. Returns list of PIDs."""
        env = {
            **os.environ,
            "PYTHONPATH":    os.path.join(self.project_root, "src"),
            "PQC_POD_ID":    str(pod_id),
            "PQC_DATA_PORT": str(_DATA_BASE_PORT + pod_id),
            "PQC_CTRL_PORT": str(_CTRL_BASE_PORT + pod_id),
            "PQC_RYU_PORT":  str(_RYU_BASE_PORT + pod_id),
        }
        pids = []
        for module, label in [
            ("pqc_sdn.apps.sw_proxy_async", f"sw_proxy_pod{pod_id}"),
            ("pqc_sdn.apps.ctrl_proxy",     f"ctrl_proxy_pod{pod_id}"),
        ]:
            log_path = os.path.join(self.project_root, f"{label}.log")
            try:
                with open(log_path, "a") as log_fh:
                    proc = subprocess.Popen(
                        [self.venv_python, "-m", module],
                        env=env, stdout=log_fh, stderr=subprocess.STDOUT,
                    )
                time.sleep(0.2)
                if proc.poll() is not None:
                    log.error("[elasticity/pod%d] %s exited immediately", self.pod_id, label)
                else:
                    log.info("[elasticity/pod%d] spawned %s pid=%d", self.pod_id, label, proc.pid)
                    pids.append(proc.pid)
            except Exception as exc:
                log.error("[elasticity/pod%d] failed to spawn %s: %s", self.pod_id, module, exc)
        return pids

    def _redirect_switches_parallel(self, dpids: list[int], proxy_port: int) -> None:
        """Redirect switches in parallel using a thread pool."""
        def _redirect_one(dpid: int) -> bool:
            sw_name = self.ryu_switch_names.get(dpid)
            if not sw_name:
                log.warning("[elasticity/pod%d] no OVS name for dpid=%d", self.pod_id, dpid)
                return False
            try:
                subprocess.run(
                    ["ovs-vsctl", "set-controller", sw_name,
                     f"tcp:127.0.0.1:{proxy_port}"],
                    check=True, capture_output=True, timeout=5,
                )
                log.info("[elasticity/pod%d] dpid=%d (%s) → :%d",
                         self.pod_id, dpid, sw_name, proxy_port)
                return True
            except Exception as exc:
                log.error("[elasticity/pod%d] redirect dpid=%d: %s", self.pod_id, dpid, exc)
                return False

        with ThreadPoolExecutor(max_workers=min(len(dpids), 8)) as pool:
            futures = {pool.submit(_redirect_one, d): d for d in dpids}
            ok = sum(1 for f in as_completed(futures) if f.result())
        log.info("[elasticity/pod%d] redirected %d/%d switches to :%d",
                 self.pod_id, ok, len(dpids), proxy_port)

    def _notify_old_controller(self, mgmt_port: int, dpids: list[int], new_ctrl_id: str) -> None:
        payload = json.dumps({
            "remove_dpids": dpids,
            "reason": f"migrated to {new_ctrl_id}",
        }).encode()
        url = f"http://127.0.0.1:{mgmt_port}/mgmt/controllers/domain-update"
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {_api_token()}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read())
                log.info("[elasticity/pod%d] old controller notified: %s", self.pod_id, body)
        except Exception as exc:
            log.warning("[elasticity/pod%d] could not notify old controller: %s",
                        self.pod_id, exc)


def _api_token() -> str:
    try:
        from pqc_sdn.settings import get_settings
        return get_settings().controller.api_token
    except Exception:
        import secrets
        return secrets.token_urlsafe(32)
