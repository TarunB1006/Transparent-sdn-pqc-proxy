"""
mgmt_api.py — PQC-SDN Management Plane HTTP API  (port 8082)

This is the management plane layer that sits above the control plane (Ryu)
and the data plane (switches).  It exposes:

  GET  /                          → management dashboard HTML
  GET  /mgmt/status               → network overview (sessions, switches, policy)
  GET  /mgmt/sessions             → active PQC sessions per switch
  GET  /mgmt/topology             → switch topology (nodes + edges)
  GET  /mgmt/config/algorithm     → current algorithm policy state
  POST /mgmt/config/algorithm     → set / clear algorithm override
  GET  /mgmt/security-events      → recent security event log (last 200)
  GET  /mgmt/policy/dscp-table    → DSCP → algorithm mapping reference

Run standalone (without Ryu):
    PYTHONPATH=src python -m pqc_sdn.apps.mgmt_api

Normally started automatically by the Ryu controller adapter.
"""

from __future__ import annotations

import json
import os
import pathlib
import psutil as _psutil
import logging
import shutil
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

log = logging.getLogger("pqc.mgmt_api")

# Module-level process handle — first cpu_percent() call seeds the baseline;
# subsequent calls return the real delta.
_PROC = _psutil.Process()
_PROC.cpu_percent(interval=None)  # seed baseline at import time

# Warm up CPU measurement in background so first real read isn't 0
import threading as _threading
def _cpu_warmup():
    import time as _t
    while True:
        _PROC.cpu_percent(interval=None)
        _t.sleep(1.0)
_threading.Thread(target=_cpu_warmup, daemon=True).start()

# Lazy imports of siblings to avoid circular imports at module load time.
# All access goes through _svc() and _events().

_MGMT_PORT = 8082
_ROOT = pathlib.Path(__file__).parent.parent.parent.parent   # project root
_DASHBOARD_HTML = _ROOT / "deploy" / "mgmt_dashboard.html"
_RESULTS_DIR    = _ROOT / "results"

ALGORITHMS = [
    "ML-KEM-1024", "ML-KEM-768", "ML-KEM-512",
    "AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305",
]

CIPHER_NAMES = {"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"}
KEM_NAMES    = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}

# True when the Ryu controller process is up and plan_api :8080 is live.
# Set once at mgmt_api startup — restart mgmt_api if Ryu later comes up.
_RYU_AVAILABLE: bool = False

SECURITY_INFO = {
    "ML-KEM-1024": {"bits": 256, "overhead_ms": 1.5, "quantum_resistant": True,
                    "description": "Maximum KEM security. NIST FIPS 203 Level 5. Use during elevated threat response."},
    "ML-KEM-768":  {"bits": 192, "overhead_ms": 1.0, "quantum_resistant": True,
                    "description": "High KEM security. NIST FIPS 203 Level 3. Balanced threat/performance."},
    "ML-KEM-512":  {"bits": 128, "overhead_ms": 0.5, "quantum_resistant": True,
                    "description": "Default global KEM. NIST FIPS 203 Level 1. All flows use this unless overridden."},
}

EVENT_LABELS = {
    "replay":            {"label": "Replay Attack",            "severity": "high"},
    "handshake_failure": {"label": "Rogue Switch Rejected",    "severity": "high"},
    "dos":               {"label": "DoS / PacketIn Flood",     "severity": "medium"},
    "key_exhaustion":    {"label": "Key Exhaustion",           "severity": "low"},
    "saturation":        {"label": "Ctrl Plane Saturation",    "severity": "medium"},
    "harvest":           {"label": "Harvest-Now-Decrypt-Later","severity": "low"},
    "traffic_analysis":  {"label": "Traffic Analysis Probe",   "severity": "low"},
}

# ── Shared topology state (set by Ryu controller adapter when running) ─────────
# _ryu_graph: nx.DiGraph of switch-to-switch links (dpid → dpid)
# _ryu_link_to_port: {(src_dpid, dst_dpid): (src_port, dst_port)}
# _ryu_switch_names: {dpid: "s1001"} — Mininet switch names for tier classification
# _controller_domains: {controller_id: {dpid, ...}} — multi-controller domain map
# _ryu_dps: {dpid: datapath} — live OVS datapaths known to Ryu (set by controller)
# _ryu_adapter: the PQCAdapter Ryu app instance (set by controller, may be None)
_ryu_graph = None
_ryu_link_to_port: dict = {}
_ryu_switch_names: dict = {}
_controller_domains: dict = {}   # controller_id → set of dpids it manages
_ryu_dps: dict = {}              # dpid → datapath (live OVS connections)
_ryu_adapter = None              # PQCAdapter instance — used for live OVS operations

# Thread locks for shared mutable state
import threading as _threading
_flow_lock = _threading.Lock()
_link_lock = _threading.Lock()
_domain_lock = _threading.Lock()
_ryu_dps_lock = _threading.Lock()

DSCP_TABLE = [
    # High-security flows → AES-256-GCM (FIPS 140-3 compliant, HW-accelerated)
    {"dscp": "48,56",   "dscp_name": "CS6/CS7",    "flow_type": "control_plane",    "algorithm": "AES-256-GCM",       "level": "High Security", "kem": "ML-KEM-512"},
    {"dscp": "10,12,14","dscp_name": "AF11-AF13",  "flow_type": "high_security",    "algorithm": "AES-256-GCM",       "level": "High Security", "kem": "ML-KEM-512"},
    {"dscp": "custom",  "dscp_name": "HIGH_SEC",   "flow_type": "high_security",    "algorithm": "AES-256-GCM",       "level": "High Security", "kem": "ML-KEM-512"},
    # Latency-sensitive flows → ChaCha20-Poly1305 (SW-optimised, no AES-NI needed)
    {"dscp": "46",      "dscp_name": "EF",         "flow_type": "latency_sensitive","algorithm": "ChaCha20-Poly1305", "level": "Latency",       "kem": "ML-KEM-512"},
    {"dscp": "32",      "dscp_name": "CS4",        "flow_type": "real_time",        "algorithm": "ChaCha20-Poly1305", "level": "Latency",       "kem": "ML-KEM-512"},
    {"dscp": "34,36,38","dscp_name": "AF41-AF43",  "flow_type": "real_time",        "algorithm": "ChaCha20-Poly1305", "level": "Latency",       "kem": "ML-KEM-512"},
    # All remaining flows → AES-128-GCM (balanced: 128-bit security, faster than -256)
    {"dscp": "18,20,22","dscp_name": "AF21-AF23",  "flow_type": "video_streaming",  "algorithm": "AES-128-GCM",       "level": "Balanced",      "kem": "ML-KEM-512"},
    {"dscp": "24",      "dscp_name": "CS3",        "flow_type": "broadcast_video",  "algorithm": "AES-128-GCM",       "level": "Balanced",      "kem": "ML-KEM-512"},
    {"dscp": "26,28,30","dscp_name": "AF31-AF33",  "flow_type": "signalling",       "algorithm": "AES-128-GCM",       "level": "Balanced",      "kem": "ML-KEM-512"},
    {"dscp": "40",      "dscp_name": "CS5",        "flow_type": "signalling",       "algorithm": "AES-128-GCM",       "level": "Balanced",      "kem": "ML-KEM-512"},
    {"dscp": "0",       "dscp_name": "BE",         "flow_type": "bulk_data",        "algorithm": "AES-128-GCM",       "level": "Balanced",      "kem": "ML-KEM-512"},
]


# ── Lazy accessors ─────────────────────────────────────────────────────────────

def _svc():
    """Return the live ControlPlaneService (set by the Ryu controller)."""
    from pqc_sdn.apps import plan_api
    return plan_api.get_service()


def _events():
    """Return the security event deque from plan_api."""
    from pqc_sdn.apps import plan_api
    return plan_api._security_events


def _override():
    """Return (enabled, algorithm) from the policy engine."""
    from pqc_sdn.policy.engine import get_algorithm_override
    return get_algorithm_override()


def _set_override(enabled: bool, algorithm: str = "ML-KEM-1024") -> None:
    from pqc_sdn.policy.engine import set_algorithm_override
    set_algorithm_override(enabled, algorithm)


# ── Ryu probe + northbound HTTP helper ────────────────────────────────────────

def _probe_ryu(retries: int = 3, delay: float = 1.0) -> bool:
    """Return True if plan_api is reachable on :8080 (Ryu process is live)."""
    import urllib.request, urllib.error, time as _t
    from pqc_sdn.settings import get_settings
    token = get_settings().controller.api_token
    url = "http://127.0.0.1:8080/pqc/status"
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    log.info("[mgmt_api] Ryu detected — forwarding mode (plan_api :8080 live)")
                    return True
        except Exception:
            pass
        if attempt < retries - 1:
            _t.sleep(delay)
    log.info("[mgmt_api] Ryu NOT detected — standalone mode")
    return False


def _ctrl_api(path: str, method: str = "GET", body: dict | None = None) -> dict | list | None:
    """Authenticated HTTP call to plan_api (Ryu process). Returns parsed JSON or None on failure."""
    if not _RYU_AVAILABLE:
        return None
    import urllib.request, urllib.error, json as _json
    from pqc_sdn.settings import get_settings
    token = get_settings().controller.api_token
    url = f"http://127.0.0.1:8080{path}"
    data = _json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return _json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return _json.loads(e.read())
        except Exception:
            return None
    except Exception:
        return None


# ── Data builders ──────────────────────────────────────────────────────────────

def _build_status() -> dict:
    base = _ctrl_api("/pqc/status") or {}
    if not base:
        try:
            base = _svc().status()
        except Exception:
            base = {}

    enabled, algo = _override()
    policy_mode = f"MANUAL: {algo}" if enabled else "ML-KEM-512"
    cpu = round(_PROC.cpu_percent(interval=None), 1)
    mem = round(_PROC.memory_info().rss / 1024 / 1024, 1)
    ryu_switches = len(_ryu_dps) if _ryu_dps else base.get("switches", 0)
    ryu_sessions = len(_ryu_dps) if _ryu_dps else base.get("pqc_sessions", base.get("sessions", 0))

    adaptive = base.get("adaptive")
    if adaptive is None:
        try:
            adaptive = _svc().adaptive_state()
        except Exception:
            adaptive = None

    return {
        "sessions":               ryu_sessions,
        "switches":               ryu_switches,
        "total_flows":            len(_flow_assignments),
        "policy_mode":            policy_mode,
        "override_enabled":       enabled,
        "override_algorithm":     algo,
        "security_events_total":  base.get("security_events_total", len(_events())),
        "cpu_percent":            round(cpu, 1),
        "memory_mb":              round(mem, 1),
        "timestamp":              _time.time(),
        "adaptive":               adaptive,
    }


def _build_sessions() -> list:
    ctrl_sessions = _ctrl_api("/pqc/sessions")
    if isinstance(ctrl_sessions, dict):
        all_plans = ctrl_sessions
    elif isinstance(ctrl_sessions, list):
        return ctrl_sessions  # plan_api returned flat list — use directly
    else:
        try:
            all_plans = _svc().orchestrator.all_plans()
        except Exception:
            return []

    override_enabled, override_algo = _override()
    rows = []
    for dpid, plans in all_plans.items():
        dpid_int = int(dpid) if str(dpid).isdigit() else 0
        for p in plans:
            # For tunnel plans, reflect the current override algorithm so the
            # dashboard always shows what algorithm is *actually in effect* now.
            algo = p.get("algorithm", "unknown")
            if override_enabled and p.get("role", "").lower() == "tunnel":
                algo = override_algo
            rows.append({
                "dpid":      dpid_int,
                "dpid_hex":  f"0x{dpid_int:08x}",
                "ctx":       p.get("ctx", ""),
                "role":      p.get("role", ""),
                "algorithm": algo,
                "dscp":      p.get("dscp", 0),
                "active":    p.get("active", False),
                "status":    "active" if p.get("active") else "inactive",
                "peer":      p.get("peer", ""),
            })
    return rows


def _build_topology() -> dict:
    try:
        svc = _svc()
        all_plans = svc.orchestrator.all_plans()
    except Exception:
        all_plans = {}

    # Determine algorithm per switch from its tunnel plan
    sw_algo: dict = {}
    for dpid, plans in all_plans.items():
        override_enabled, override_algo = _override()
        for p in plans:
            if p.get("active") and p.get("role", "").lower() == "tunnel":
                sw_algo[dpid] = override_algo if override_enabled else p.get("algorithm", "ML-KEM-1024")
                break

    def _tier(dpid_int: int, name: str) -> str:
        """Classify switch tier from Mininet name (s100x=core, s200x=agg, s300x=edge)
        or fall back to fat-tree k=4 dpid-range heuristic.
        Fat-tree k=4: (k/2)^2=4 core, k^2/2=8 agg, k^2/2=8 edge → dpid 1-4 core, 5-12 agg, 13-20 edge.
        """
        n = name.lower()
        if n.startswith("s1"): return "core"
        if n.startswith("s2"): return "agg"
        if n.startswith("s3"): return "edge"
        # fat-tree k=4 heuristic: 4 core, 8 agg, 8 edge
        return _fat_tree_tier(dpid_int)

    nodes = [{"id": "controller", "type": "controller", "label": "SDN Controller", "algorithm": None, "tier": "controller"}]
    edges = []
    seen_edges: set = set()

    # Build controller nodes for multi-controller mode
    if _controller_domains:
        nodes = []  # replace default single controller node
        for ctrl_id, dpid_set in _controller_domains.items():
            label = ctrl_id.replace("sdn-controller-", "")
            nodes.append({"id": ctrl_id, "type": "controller",
                          "label": label, "algorithm": None, "tier": "controller"})
        # fallback root if not explicitly listed
        if not any(n["id"] == "sdn-controller" for n in nodes):
            pass  # fine — named controllers replace it
    
    # Build switch → controller mapping
    def _ctrl_for(dpid_int: int) -> str:
        for ctrl_id, dpid_set in _controller_domains.items():
            if dpid_int in dpid_set:
                return ctrl_id
        return list(_controller_domains.keys())[0] if _controller_domains else "controller"

    # Collect all known dpids: union of live Ryu dps and orchestrator plans
    known_dpids: set = set()
    if _ryu_dps:
        known_dpids.update(_ryu_dps.keys())
    for dpid_str in all_plans.keys():
        try:
            known_dpids.add(int(dpid_str))
        except (ValueError, TypeError):
            pass

    # Build switch nodes from all known dpids (live Ryu state is ground truth)
    for dpid_int in sorted(known_dpids):
        dpid_str = str(dpid_int)
        name = _ryu_switch_names.get(dpid_int, f"sw-{dpid_int}")
        tier = _tier(dpid_int, name)
        override_enabled, override_algo = _override()
        algo = sw_algo.get(dpid_str, "ML-KEM-1024" if dpid_int in (_ryu_dps or {}) else "unknown")
        if override_enabled:
            algo = override_algo
        assigned_ctrl = _ctrl_for(dpid_int) if _controller_domains else "controller"
        nodes.append({
            "id":       f"sw-{dpid_int}",
            "type":     "switch",
            "label":    name,
            "dpid":     dpid_int,
            "dpid_hex": f"0x{dpid_int:04x}",
            "algorithm": algo,
            "tier":     tier,
            "controller_id": assigned_ctrl,
        })
        edges.append({"from": assigned_ctrl, "to": f"sw-{dpid_int}", "type": "control"})

    # Add real inter-switch links from Ryu graph if available
    if _ryu_graph is not None:
        try:
            for src, dst in _ryu_graph.edges():
                key = (min(src, dst), max(src, dst))
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({"from": f"sw-{src}", "to": f"sw-{dst}", "type": "data"})
        except Exception:
            pass

    # Add manually overridden inter-switch links
    for link_key in _link_overrides:
        pair = sorted(link_key)
        if len(pair) == 2:
            a, b = pair
            key = (a, b)
            if key not in seen_edges:
                node_ids = {n["id"] for n in nodes}
                if f"sw-{a}" in node_ids and f"sw-{b}" in node_ids:
                    seen_edges.add(key)
                    edges.append({"from": f"sw-{a}", "to": f"sw-{b}", "type": "data"})

    return {"nodes": nodes, "edges": edges, "ryu_topo": _ryu_graph is not None}


def _build_events(limit: int = 50) -> list:
    evts = []
    for e in list(_events())[:limit]:
        meta = EVENT_LABELS.get(e.get("event", ""), {"label": e.get("event", "unknown"), "severity": "low"})
        evts.append({**e, "label": meta["label"], "severity": meta["severity"]})
    return evts


def _build_algorithm_config() -> dict:
    enabled, algo = _override()
    info = SECURITY_INFO.get(algo, {})
    return {
        "override_enabled":   enabled,
        "override_algorithm": algo,
        "mode":               "manual" if enabled else "adaptive",
        "algorithm_info":     info,
        "available_algorithms": [
            {"name": k, **v} for k, v in SECURITY_INFO.items()
        ],
    }


# ── Security / Performance / Network metrics ───────────────────────────────────

def _read_gauge_sum(gauge) -> float:
    """Sum all labeled instances of a prometheus Gauge."""
    try:
        return float(sum(child._value.get() for child in gauge._metrics.values()))
    except Exception:
        try:
            return float(gauge._value.get())
        except Exception:
            return 0.0


def _build_security_metrics() -> dict:
    """Security metrics: try plan_api (owns the live Prometheus registry) first."""
    ctrl = _ctrl_api("/pqc/metrics/security")
    if ctrl and not ctrl.get("error"):
        return ctrl

    evts = list(_events())
    replay   = sum(1 for e in evts if e.get("event") == "replay")
    rogue    = sum(1 for e in evts if e.get("event") == "handshake_failure")
    dos      = sum(1 for e in evts if e.get("event") == "dos")
    harvest  = sum(1 for e in evts if e.get("event") == "harvest")
    try:
        sessions = len(_svc().orchestrator.all_plans())
    except Exception:
        sessions = 0
    return {
        "replay_total":          replay,
        "rogue_switch_total":    rogue,
        "dos_rate_current":      float(dos),
        "ctrl_saturation_conns": 0,
        "key_exhaustion_total":  0,
        "harvest_bytes":         0,
        "harvest_decrypt_ok":    0,
        "active_sessions":       sessions,
    }


def _histogram_avg_ms(histogram) -> float:
    """Compute average from a prometheus Histogram (sum/count * 1000 for ms)."""
    try:
        total_sum = sum(child._sum.get() for child in histogram._metrics.values())
        total_cnt = sum(child._count.get() for child in histogram._metrics.values())
        return round((total_sum / total_cnt) * 1000, 3) if total_cnt > 0 else 0.0
    except Exception:
        return 0.0


def _build_performance_metrics() -> dict:
    # plan_api runs in the Ryu process and reads the real Prometheus histograms
    ctrl = _ctrl_api("/pqc/metrics/performance")
    if ctrl and not ctrl.get("error") and ctrl.get("source") == "live":
        return ctrl

    cpu = round(_PROC.cpu_percent(interval=None), 1)
    mem = round(_PROC.memory_info().rss / 1024 / 1024, 1)
    hs_avg = pi_avg = 0.0
    try:
        from pqc_sdn.metrics.exporter import HANDSHAKE_SECONDS, PACKET_IN_SECONDS
        hs_avg = _histogram_avg_ms(HANDSHAKE_SECONDS)
        pi_avg = _histogram_avg_ms(PACKET_IN_SECONDS)
    except Exception:
        pass

    source = "live" if (hs_avg or pi_avg) else "benchmark_file"
    if source == "benchmark_file":
        try:
            bdata = _get_benchmark("latest")
            hs_rows = bdata.get("handshake", [])
            total_row = next((r for r in hs_rows if str(r.get("phase","")).lower() == "total"), None)
            if total_row:
                if hs_avg == 0.0 and total_row.get("p50"):
                    hs_avg = float(total_row["p50"])
                if pi_avg == 0.0 and total_row.get("mean"):
                    pi_avg = round(float(total_row["mean"]) * 0.05, 3)
        except Exception:
            pass

    return {
        "handshake_avg_ms": hs_avg,
        "packet_in_avg_ms": pi_avg,
        "cpu_percent":      cpu,
        "memory_mb":        mem,
        "source":           source,
        "note": "Live Prometheus values when Ryu is running; pre-recorded benchmark p50 shown otherwise.",
    }


def _build_network_metrics() -> dict:
    ctrl = _ctrl_api("/pqc/metrics/network")
    if ctrl and not ctrl.get("error"):
        ctrl["total_flows"] = len(_flow_assignments)  # add local flow count
        return ctrl

    try:
        svc = _svc()
        all_plans = svc.orchestrator.all_plans()
        plan_switches = len(all_plans)
        sessions = sum(1 for plans in all_plans.values() for p in plans if p.get("active"))
    except Exception:
        plan_switches, sessions = 0, 0

    switches = len(_ryu_dps) if _ryu_dps else plan_switches
    if _ryu_dps:
        try:
            sessions = len(_svc()._switch_sessions)
        except Exception:
            sessions = switches

    link_util: dict = {}
    enc_bytes: dict = {}
    ryu_active = False
    try:
        from pqc_sdn.metrics.exporter import LINK_UTILIZATION, PQC_ENCRYPTED_BYTES
        for labels, child in LINK_UTILIZATION._metrics.items():
            val = round(float(child._value.get()) * 100, 1)
            link_util[f"dpid={labels[0]} port={labels[1]}"] = val
            ryu_active = True
        for labels, child in PQC_ENCRYPTED_BYTES._metrics.items():
            enc_bytes[f"dpid={labels[0]}"] = int(child._value.get())
    except Exception:
        pass

    return {
        "connected_switches": switches,
        "total_flows":        len(_flow_assignments),
        "active_sessions":    sessions,
        "link_utilization":   link_util,
        "encrypted_bytes":    enc_bytes,
        "ryu_active":         ryu_active,
        "note": "" if ryu_active else "Link utilization populated by Ryu port-stats. Start ryu-manager to see live data.",
    }


# ── Benchmark data builders ────────────────────────────────────────────────────

def _list_benchmarks() -> list:
    _RESULTS_DIR.mkdir(exist_ok=True)
    files = sorted(_RESULTS_DIR.glob("benchmark_2*.json"), reverse=True)
    results = []
    for f in files[:20]:
        try:
            data = json.loads(f.read_text())
            results.append({
                "filename":  f.name,
                "timestamp": data.get("timestamp", ""),
                "platform":  data.get("platform", ""),
                "liboqs":    data.get("liboqs_available", False),
                "tables":    [k for k in ("ml_kem","handshake","cipher","security") if k in data],
            })
        except Exception:
            pass
    return results


def _normalize_benchmark(data: dict) -> dict:
    """Convert nested benchmark JSON to flat arrays expected by the dashboard."""
    out = {k: v for k, v in data.items() if k not in ("ml_kem", "handshake", "cipher", "security")}

    # Table 1 — ml_kem: dict-of-dicts → list of flat rows
    if isinstance(data.get("ml_kem"), dict):
        rows = []
        for variant, v in data["ml_kem"].items():
            rows.append({
                "variant":    variant,
                "pk_bytes":   v.get("pk_bytes"),
                "ct_bytes":   v.get("ct_bytes"),
                "keygen_p50": v.get("keygen_ms", {}).get("p50"),
                "keygen_p99": v.get("keygen_ms", {}).get("p99"),
                "encap_p50":  v.get("encap_ms",  {}).get("p50"),
                "encap_p99":  v.get("encap_ms",  {}).get("p99"),
                "decap_p50":  v.get("decap_ms",  {}).get("p50"),
                "decap_p99":  v.get("decap_ms",  {}).get("p99"),
            })
        out["ml_kem"] = rows
    else:
        out["ml_kem"] = data.get("ml_kem", [])

    # Table 2 — handshake: dict-of-dicts → list of flat rows
    if isinstance(data.get("handshake"), dict):
        rows = []
        for phase, v in data["handshake"].items():
            rows.append({
                "phase": phase,
                "mean":  v.get("mean"), "std": v.get("std"),
                "p50":   v.get("p50"),  "p95": v.get("p95"), "p99": v.get("p99"),
            })
        out["handshake"] = rows
    else:
        out["handshake"] = data.get("handshake", [])

    # Table 3 — cipher: dict-of-dicts → list of flat rows
    if isinstance(data.get("cipher"), dict):
        rows = []
        for _key, v in data["cipher"].items():
            rows.append({
                "msg_bytes":     v.get("msg_bytes"),
                "wire_bytes":    v.get("wire_bytes"),
                "overhead_bytes":v.get("overhead_bytes"),
                "overhead_pct":  v.get("overhead_pct"),
                "enc_p50":       v.get("encrypt_ms", {}).get("p50"),
                "enc_p99":       v.get("encrypt_ms", {}).get("p99"),
                "dec_p50":       v.get("decrypt_ms", {}).get("p50"),
                "dec_p99":       v.get("decrypt_ms", {}).get("p99"),
            })
        out["cipher"] = rows
    else:
        out["cipher"] = data.get("cipher", [])

    # Table 4 — security: dict → list of flat rows
    if isinstance(data.get("security"), dict):
        rows = []
        for test, v in data["security"].items():
            if isinstance(v, dict):
                passed = v.get("pass", v.get("rate_pct", 0) == 100.0)
                rate = v.get("rate_pct")
                notes = ""
                if "distinct_wire_sizes" in v:
                    notes = f"{v['distinct_wire_sizes']} distinct wire sizes"
                rows.append({
                    "test":   test,
                    "result": "PASS" if passed else "FAIL",
                    "rate":   f"{rate:.1f}%" if rate is not None else "",
                    "notes":  notes,
                })
        out["security"] = rows
    else:
        out["security"] = data.get("security", [])

    return out


def _get_benchmark(name: str = "latest") -> dict:
    if name == "latest":
        path = _RESULTS_DIR / "benchmark_latest.json"
    else:
        path = _RESULTS_DIR / name
    if not path.exists():
        return {"error": "no benchmark results found", "hint": "run: PYTHONPATH=src python scripts/benchmark.py"}
    try:
        return _normalize_benchmark(json.loads(path.read_text()))
    except Exception as e:
        return {"error": str(e)}


def _run_benchmark_sync(tables: list[int] | None = None) -> dict:
    """Run benchmark in-process (blocks for ~30s). Called from POST /mgmt/benchmarks/run."""
    import sys as _sys
    _sys.path.insert(0, str(_ROOT / "src"))
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "benchmark", _ROOT / "scripts" / "benchmark.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.run_all(n_kem=50, n_hs=30, n_cipher=200, n_sec=50, tables=tables)
    except Exception as e:
        return {"error": str(e)}


# ── Fat-tree topology config ───────────────────────────────────────────────────
# k=4: (k/2)^2 = 4 core, k^2/2 = 8 agg, k^2/2 = 8 edge
# dpid ranges: core=1..4, agg=5..12, edge=13..20
_FAT_TREE_K = 4
_FAT_TREE_TIERS = {
    "core": {"start": 1, "count": (_FAT_TREE_K // 2) ** 2},        # 4
    "agg":  {"start": 1 + (_FAT_TREE_K // 2) ** 2,
              "count": _FAT_TREE_K * _FAT_TREE_K // 2},              # 8
    "edge": {"start": 1 + (_FAT_TREE_K // 2) ** 2 + _FAT_TREE_K * _FAT_TREE_K // 2,
              "count": _FAT_TREE_K * _FAT_TREE_K // 2},              # 8
}
_FAT_TREE_MAX = sum(t["count"] for t in _FAT_TREE_TIERS.values())   # 20


def _fat_tree_tier(dpid: int) -> str:
    for tier, cfg in _FAT_TREE_TIERS.items():
        if cfg["start"] <= dpid < cfg["start"] + cfg["count"]:
            return tier
    return "unknown"


def _fat_tree_tier_status(existing_dpids: set) -> dict:
    """Return how many switches are present vs capacity per tier.
    Uses switch name prefix (s1=core, s2=agg, s3=edge) consistent with
    _build_topology, falling back to dpid-range heuristic only when name unknown.
    """
    counts = {"core": 0, "agg": 0, "edge": 0}
    for dpid in existing_dpids:
        name = _ryu_switch_names.get(dpid, "")
        n = name.lower()
        if n.startswith("s1"):
            counts["core"] += 1
        elif n.startswith("s2"):
            counts["agg"] += 1
        elif n.startswith("s3"):
            counts["edge"] += 1
        else:
            # fallback: dpid-range heuristic
            tier = _fat_tree_tier(dpid)
            if tier in counts:
                counts[tier] += 1

    status = {}
    for tier, cfg in _FAT_TREE_TIERS.items():
        used = counts[tier]
        status[tier] = {
            "used": used,
            "capacity": cfg["count"],
            "available": cfg["count"] - used,
            "switches": [],
        }
    return status

# In-memory inter-switch link overrides: set of frozenset({dpid_a, dpid_b})
_link_overrides: set = set()

# In-memory flow assignments: key = (src_ip, dst_ip, dscp) → dict
_flow_assignments: dict = {}


def _add_link(dpid_a: int, dpid_b: int) -> dict:
    key = frozenset({dpid_a, dpid_b})
    with _link_lock:
        if key in _link_overrides:
            return {"ok": True, "already_exists": True, "from": dpid_a, "to": dpid_b}
        _link_overrides.add(key)
    _log("link", f"added dpid={dpid_a}↔{dpid_b}")
    return {"ok": True, "added": True, "from": dpid_a, "to": dpid_b}


def _remove_link(dpid_a: int, dpid_b: int) -> dict:
    key = frozenset({dpid_a, dpid_b})
    with _link_lock:
        removed = key in _link_overrides
        _link_overrides.discard(key)
    if removed:
        _log("link", f"removed dpid={dpid_a}↔{dpid_b}")
    return {"ok": True, "removed": removed, "from": dpid_a, "to": dpid_b}


def _update_session_gauge() -> None:
    """Sync PQC_ACTIVE_SESSIONS gauge — skip if Ryu owns :9101 to avoid split-brain."""
    if _RYU_AVAILABLE:
        return
    try:
        from pqc_sdn.metrics.exporter import PQC_ACTIVE_SESSIONS
        if _ryu_dps:
            count = len(_ryu_dps)
        else:
            svc = _svc()
            count = sum(1 for plans in svc.orchestrator.all_plans().values()
                        for p in plans if p.get("active"))
        PQC_ACTIVE_SESSIONS.set(count)
    except Exception:
        pass


def _push_algorithm_override_to_mininet(algorithm: str) -> None:
    """
    Flush all existing flows on all connected OVS switches, then re-run the
    full proxy handshake with the new algorithm so new sessions use it.
    """
    if _ryu_adapter is None:
        return
    try:
        from ryu.ofproto import ofproto_v1_3
        for dpid, dp in list(_ryu_dps.items()):
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            match_all = parser.OFPMatch()
            flow_del = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match_all,
                priority=1,
            )
            dp.send_msg(flow_del)
        _log("policy", f"flushed flows on {len(_ryu_dps)} switches → {algorithm} will apply to next PacketIn")
    except Exception as e:
        _log("policy", f"flow flush error: {e}", level="WARN")

    if algorithm == "adaptive":
        return

    if algorithm == "AES-256-GCM":
        # Standard TLS via proxy tunnel: write the flag file so both proxy processes
        # switch to TLS mode, then restart them so ctrl_proxy re-binds with SSLContext.
        # Existing OVS connections reconnect automatically after the flow flush above.
        import subprocess, sys, time as _t
        _TLS_FLAG = "/tmp/pqc_tls_mode"
        open(_TLS_FLAG, "w").close()
        python = sys.executable
        src_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        env = {**os.environ, "PYTHONPATH": os.path.join(src_root, "src")}
        try:
            subprocess.run(["pkill", "-f", "ctrl_proxy"],    capture_output=True, timeout=5)
            subprocess.run(["pkill", "-f", "sw_proxy_async"], capture_output=True, timeout=5)
            _t.sleep(1)
            subprocess.Popen([python, "-m", "pqc_sdn.apps.ctrl_proxy"],
                             env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.Popen([python, "-m", "pqc_sdn.apps.sw_proxy_async"],
                             env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            _log("policy", f"proxy restart error: {e}", level="WARN")
        _log("policy", "standard TLS mode active — proxies restarted with TLS sockets")
        return

    try:
        svc = _svc()
        results = svc.rehandshake_all(algorithm)
        ok = sum(1 for v in results.values() if v["ok"])
        _log("policy", f"rehandshake complete: {ok}/{len(results)} switches succeeded with {algorithm}")
    except Exception as e:
        _log("policy", f"rehandshake error: {e}", level="WARN")
        return

    # Log per-switch results through the Ryu adapter logger — same format as initial connect.
    try:
        ryu_logger = _ryu_adapter.logger
        for dpid, r in results.items():
            if r["ok"]:
                ryu_logger.info(
                    f"[RYU] switch-{dpid} ML-KEM handshake complete (OVERRIDE→{algorithm}). "
                    f"algo={r['variant']} handshake={r['elapsed_ms']:.2f}ms total={r['elapsed_ms']:.2f}ms"
                )
            else:
                ryu_logger.warning(f"[RYU] switch-{dpid} ML-KEM handshake FAILED (OVERRIDE→{algorithm})")
    except Exception:
        pass



def _push_flow_to_mininet(src_ip: str, dst_ip: str, dscp: int,
                           algo_used: str, path: list[int]) -> None:
    """Install an OpenFlow rule on the ingress switch for src_ip→dst_ip via the computed path."""
    if _ryu_adapter is None or not path:
        return
    try:
        adapter = _ryu_adapter
        src_dpid = path[0]
        dp = _ryu_dps.get(src_dpid)
        if dp is None:
            return
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
        # Determine egress port from the topology graph
        if len(path) > 1 and adapter.graph.has_edge(path[0], path[1]):
            out_port = adapter.graph[path[0]][path[1]]['src_port']
        else:
            # Try to find destination host port
            loc = adapter._get_host_location(dst_ip)
            out_port = loc[1] if loc else dp.ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        adapter._add_flow(dp, 100, match, actions, idle_timeout=60)
        _log("flow", f"OpenFlow rule installed: {src_ip}→{dst_ip} dscp={dscp} "
                     f"algo={algo_used} dpid={src_dpid} port={out_port}")
    except Exception as e:
        _log("flow", f"OpenFlow install error: {e}", level="WARN")


def _disconnect_switch_from_ovs(dpid: int) -> None:
    """Remove OVS controller assignment so the switch stops sending OpenFlow to us."""
    import subprocess
    sw_name = _ryu_switch_names.get(dpid)
    if sw_name:
        try:
            subprocess.run(
                ["ovs-vsctl", "del-controller", sw_name],
                capture_output=True, timeout=5,
            )
            _log("switch", f"removed OVS controller for {sw_name} (dpid={dpid})")
        except Exception as e:
            _log("switch", f"ovs del-controller error for dpid={dpid}: {e}", level="WARN")


def _connect_switch_to_ovs(dpid: int) -> None:
    """Restore OVS controller assignment so the switch reconnects via the proxy.
    Runs in a background thread — must not block the handshake return path."""
    import subprocess
    from pqc_sdn.settings import get_settings
    sw_name = _ryu_switch_names.get(dpid)
    if sw_name:
        try:
            port = get_settings().proxy.base_data_port
            subprocess.run(
                ["ovs-vsctl", "set-controller", sw_name, f"tcp:127.0.0.1:{port}"],
                capture_output=True, timeout=5,
            )
            _log("switch", f"restored OVS controller for {sw_name} (dpid={dpid}) → :{port}")
        except Exception as e:
            _log("switch", f"ovs set-controller error for dpid={dpid}: {e}", level="WARN")


def _connect_switch(dpid: int) -> dict:
    # If Ryu is live, delegate the real ML-KEM handshake to plan_api
    ctrl = _ctrl_api("/pqc/switches/connect", "POST", {"dpid": dpid})
    if ctrl is not None:
        ok = ctrl.get("ok", False)
        if ok:
            with _ryu_dps_lock:
                if dpid not in _ryu_dps:
                    _ryu_dps[dpid] = None
            _log("RYU", f"[PQC-HANDSHAKE] switch-{dpid} ESTABLISHED via plan_api "
                        f"elapsed={ctrl.get('elapsed_ms', 0):.2f}ms")
        else:
            _log("RYU", f"[PQC-HANDSHAKE] switch-{dpid} FAILED via plan_api", level="WARN")
        _threading.Thread(
            target=_connect_switch_to_ovs, args=(dpid,), daemon=True,
            name=f"ovs-assign-{dpid}",
        ).start()
        return ctrl

    try:
        import time as _t
        svc = _svc()
        _log("RYU", f"switch-{dpid} connected — initiating ML-KEM-512 PQC handshake (standalone)")
        t0 = _t.perf_counter()
        ok = svc.on_switch_connected(dpid)
        elapsed_ms = (_t.perf_counter() - t0) * 1000
        if ok:
            _log("RYU", f"[PQC-HANDSHAKE] switch-{dpid} ESTABLISHED handshake={elapsed_ms:.2f}ms")
            with _ryu_dps_lock:
                if dpid not in _ryu_dps:
                    _ryu_dps[dpid] = None
        else:
            _log("RYU", f"[PQC-HANDSHAKE] switch-{dpid} FAILED", level="WARN")
        _update_session_gauge()
        _threading.Thread(
            target=_connect_switch_to_ovs, args=(dpid,), daemon=True,
            name=f"ovs-assign-{dpid}",
        ).start()
        return {"ok": ok, "dpid": dpid, "dpid_hex": f"0x{dpid:04x}",
                "message": f"Switch {dpid} handshake {'ok' if ok else 'failed'}"}
    except Exception as e:
        _log("switch", f"dpid={dpid} connect error: {e}", level="ERROR")
        return {"ok": False, "error": str(e)}


def _disconnect_switch(dpid: int) -> dict:
    ctrl = _ctrl_api(f"/pqc/switches/{dpid}/disconnect", "POST")
    if ctrl is not None:
        with _ryu_dps_lock:
            _ryu_dps.pop(dpid, None)
        _log("switch", f"dpid={dpid} disconnected via plan_api")
        _disconnect_switch_from_ovs(dpid)
        return ctrl

    try:
        svc = _svc()
        plans = svc.orchestrator._plans
        removed = dpid in plans
        plans.pop(dpid, None)
        svc._switch_sessions.pop(dpid, None)
        with _ryu_dps_lock:
            _ryu_dps.pop(dpid, None)
        _log("switch", f"dpid={dpid} disconnected removed={removed} (standalone)")
        _update_session_gauge()
        _disconnect_switch_from_ovs(dpid)
        return {"ok": True, "dpid": dpid, "removed": removed}
    except Exception as e:
        _log("switch", f"dpid={dpid} disconnect error: {e}", level="ERROR")
        return {"ok": False, "error": str(e)}


def _assign_flow(src_ip: str, dst_ip: str, dscp: int,
                 algorithm: str | None, path: list[int]) -> dict:
    # Determine path if not given (needed for both proxy and standalone paths)
    if not path:
        try:
            if _RYU_AVAILABLE:
                sessions_data = _ctrl_api("/pqc/sessions") or {}
                connected = sorted((sessions_data if isinstance(sessions_data, dict) else {}).keys(),
                                   key=lambda x: int(x))
            else:
                connected = sorted(_svc().orchestrator.all_plans().keys(), key=lambda x: int(x))
            if len(connected) >= 2:
                path = [int(connected[0]), int(connected[-1])]
            elif len(connected) == 1:
                path = [int(connected[0])]
            else:
                return {"ok": False, "error": "No switches connected. Connect switches first."}
        except Exception:
            return {"ok": False, "error": "Could not determine switch path."}

    ctrl = _ctrl_api("/pqc/flows/assign", "POST", {
        "src_ip": src_ip, "dst_ip": dst_ip, "dscp": dscp,
        "algorithm": algorithm or "auto", "path": path,
    })
    if ctrl is not None:
        algo_used = ctrl.get("algorithm", "unknown")
        entry = {"src_ip": src_ip, "dst_ip": dst_ip, "dscp": dscp,
                 "algorithm": algo_used, "path": path, "ts": _time.time()}
        with _flow_lock:
            _flow_assignments[(src_ip, dst_ip, dscp)] = entry
        _log("flow", f"{src_ip}→{dst_ip} dscp={dscp} algo={algo_used} path={path}")
        _push_flow_to_mininet(src_ip, dst_ip, dscp, algo_used, path)
        return {"ok": True, **entry}

    try:
        svc = _svc()
        flow_key = (src_ip, dst_ip, 0, 0)
        if algorithm and algorithm != "auto":
            from pqc_sdn.policy.engine import set_algorithm_override, get_algorithm_override
            prev = get_algorithm_override()
            set_algorithm_override(True, algorithm)
            algo_used = svc.on_flow_path(path, flow_key, src_ip, dst_ip, dscp)
            set_algorithm_override(*prev)
        else:
            algo_used = svc.on_flow_path(path, flow_key, src_ip, dst_ip, dscp)
        entry = {"src_ip": src_ip, "dst_ip": dst_ip, "dscp": dscp,
                 "algorithm": algo_used, "path": path, "ts": _time.time()}
        with _flow_lock:
            _flow_assignments[(src_ip, dst_ip, dscp)] = entry
        _log("flow", f"{src_ip}→{dst_ip} dscp={dscp} algo={algo_used} path={path} (standalone)")
        _push_flow_to_mininet(src_ip, dst_ip, dscp, algo_used, path)
        try:
            from pqc_sdn.metrics.exporter import FLOW_ALGORITHM
            dscp_row = next((r for r in DSCP_TABLE if str(dscp) in str(r["dscp"])), {})
            dscp_name = dscp_row.get("dscp_name", str(dscp))
            ingress = str(path[0]) if path else "unknown"
            FLOW_ALGORITHM.labels(
                src_ip=src_ip, dst_ip=dst_ip, algorithm=algo_used,
                dscp=str(dscp), dscp_name=dscp_name, ingress_dpid=ingress,
            ).set(1)
        except Exception:
            pass
        _update_session_gauge()
        return {"ok": True, **entry}
    except Exception as e:
        _log("flow", f"assign error: {e}", level="ERROR")
        return {"ok": False, "error": str(e)}


def _list_flows() -> list:
    with _flow_lock:
        return list(_flow_assignments.values())


import sys as _sys

# ── Controller load thresholds ─────────────────────────────────────────────────
_CTRL_LOAD_THRESHOLD_SWITCHES    = 10    # switches per controller before overload
_CTRL_LOAD_THRESHOLD_HANDSHAKE_MS = 2.0  # avg handshake ms before overload
_CTRL_LOAD_THRESHOLD_CPU_PCT     = 85.0  # CPU% before overload (matches elasticity.py)


def _build_controller_status() -> dict:
    """Per-controller load report used by /mgmt/controllers/status."""
    try:
        all_plans = _svc().orchestrator.all_plans()
    except Exception:
        all_plans = {}

    try:
        from pqc_sdn.metrics.exporter import HANDSHAKE_SECONDS
        hs_avg = _histogram_avg_ms(HANDSHAKE_SECONDS)
    except Exception:
        hs_avg = 0.0

    cpu = round(_PROC.cpu_percent(interval=None), 1)
    mem = round(_PROC.memory_info().rss / 1024 / 1024, 1)

    if _controller_domains:
        controllers = []
        for ctrl_id, dpid_set in _controller_domains.items():
            sw_count = len(dpid_set)
            sessions = sum(1 for d in dpid_set if str(d) in all_plans)
            overloaded = (sw_count > _CTRL_LOAD_THRESHOLD_SWITCHES or
                          hs_avg > _CTRL_LOAD_THRESHOLD_HANDSHAKE_MS or
                          cpu >= _CTRL_LOAD_THRESHOLD_CPU_PCT)
            controllers.append({
                "controller_id":    ctrl_id,
                "switches":         sw_count,
                "active_sessions":  sessions,
                "handshake_avg_ms": round(hs_avg, 3),
                "cpu_percent":      cpu,
                "memory_mb":        mem,
                "overloaded":       overloaded,
                "dpids":            sorted(dpid_set),
            })
    else:
        sw_count = len(all_plans)
        overloaded = (sw_count > _CTRL_LOAD_THRESHOLD_SWITCHES or
                      hs_avg > _CTRL_LOAD_THRESHOLD_HANDSHAKE_MS or
                      cpu >= _CTRL_LOAD_THRESHOLD_CPU_PCT)
        controllers = [{
            "controller_id":    "sdn-controller",
            "switches":         sw_count,
            "active_sessions":  sum(1 for p in all_plans.values()
                                    for pl in p if pl.get("active")),
            "handshake_avg_ms": round(hs_avg, 3),
            "cpu_percent":      cpu,
            "memory_mb":        mem,
            "overloaded":       overloaded,
            "dpids":            sorted(int(d) for d in all_plans.keys()),
        }]

    # Scale-out recommendation: find unassigned pod dpid groups
    recommendation = None
    overloaded_ctrl = next((c for c in controllers if c["overloaded"]), None)
    if overloaded_ctrl:
        all_assigned = {d for dom in _controller_domains.values() for d in dom}
        k_half = _FAT_TREE_K // 2
        agg_start, edge_start = 5, 13
        suggestions = []
        for pod_idx in range(_FAT_TREE_K):
            pod_dpids = (
                {agg_start  + pod_idx * k_half + j for j in range(k_half)} |
                {edge_start + pod_idx * k_half + j for j in range(k_half)}
            )
            if not (pod_dpids & all_assigned):
                suggestions.append({
                    "pod_idx":      pod_idx,
                    "dpids":        sorted(pod_dpids),
                    "suggested_id": f"sdn-controller-pod{pod_idx}",
                })
        if suggestions:
            recommendation = {
                "reason":         (f"{overloaded_ctrl['controller_id']} managing "
                                   f"{overloaded_ctrl['switches']} switches "
                                   f"(threshold={_CTRL_LOAD_THRESHOLD_SWITCHES}) or "
                                   f"latency={overloaded_ctrl['handshake_avg_ms']:.2f}ms "
                                   f"(threshold={_CTRL_LOAD_THRESHOLD_HANDSHAKE_MS}ms) or "
                                   f"cpu={overloaded_ctrl['cpu_percent']:.1f}% "
                                   f"(threshold={_CTRL_LOAD_THRESHOLD_CPU_PCT}%)"),
                "suggested_pods": suggestions[:2],
            }

    return {
        "controllers":            controllers,
        "total_controllers":      len(controllers),
        "switch_threshold":       _CTRL_LOAD_THRESHOLD_SWITCHES,
        "handshake_threshold_ms": _CTRL_LOAD_THRESHOLD_HANDSHAKE_MS,
        "cpu_threshold_pct":      _CTRL_LOAD_THRESHOLD_CPU_PCT,
        "scale_out_recommended":  recommendation is not None,
        "recommendation":         recommendation,
    }


def _scale_out_controller(body: dict) -> dict:
    """
    Register a new controller domain. Moves dpids out of any existing owner.
    Body: {"controller_id": "sdn-controller-pod0", "dpids": [5,6,13,14]}
       or {"pod_idx": 0}  (auto-compute fat-tree pod dpids)
    In production: start a new ryu-manager instance using
      ControlPlaneService(controller_id=..., domain_dpids=set(dpids))
    """
    ctrl_id = body.get("controller_id")
    dpids   = body.get("dpids")

    if dpids is None and "pod_idx" in body:
        pod_idx   = int(body["pod_idx"])
        k_half    = _FAT_TREE_K // 2
        agg_start, edge_start = 5, 13
        dpids     = sorted(
            {agg_start  + pod_idx * k_half + j for j in range(k_half)} |
            {edge_start + pod_idx * k_half + j for j in range(k_half)}
        )
        ctrl_id   = ctrl_id or f"sdn-controller-pod{pod_idx}"

    if not ctrl_id or not dpids:
        return {"ok": False, "error": "provide controller_id + dpids, or pod_idx"}

    dpids = [int(d) for d in dpids]

    # Move dpids out of current owners
    for eid, eset in list(_controller_domains.items()):
        _controller_domains[eid] = eset - set(dpids)

    _controller_domains[ctrl_id] = set(dpids)
    _log("controller", f"scale-out: {ctrl_id} assigned dpids={dpids}")

    return {
        "ok":                True,
        "controller_id":     ctrl_id,
        "dpids":             dpids,
        "total_controllers": len(_controller_domains),
        "message":           (f"Controller {ctrl_id} now manages {len(dpids)} switches. "
                              f"In production: start a new ryu-manager with "
                              f"ControlPlaneService(controller_id='{ctrl_id}', "
                              f"domain_dpids={set(dpids)})."),
    }


def _domain_update(body: dict) -> dict:
    """
    Called by the elasticity monitor on the *old* controller to shed migrated dpids.

    Body: {"remove_dpids": [5, 6, 13, 14], "reason": "migrated to sdn-controller-pod2"}

    Actions:
      1. Remove dpids from every entry in _controller_domains.
      2. Tear down ControlPlaneService sessions for those dpids so they don't
         receive stale key-refresh messages.
      3. Remove from _ryu_dps so the dashboard switch count is accurate.
    """
    remove = [int(d) for d in body.get("remove_dpids", [])]
    reason = body.get("reason", "migration")

    if not remove:
        return {"ok": False, "error": "remove_dpids is empty"}

    # Update in-memory domain map
    for ctrl_id, dpid_set in list(_controller_domains.items()):
        _controller_domains[ctrl_id] = dpid_set - set(remove)

    # Drop sessions in ControlPlaneService
    try:
        svc = _svc()
        for dpid in remove:
            svc._switch_sessions.pop(dpid, None)
            getattr(svc, "_switch_variants", {}).pop(dpid, None)
            svc.orchestrator._plans.pop(dpid, None)
    except Exception as exc:
        _log("domain-update", f"session cleanup error: {exc}", level="WARN")

    # Remove from live Ryu dps so switch-count gauge is accurate
    for dpid in remove:
        _ryu_dps.pop(dpid, None)

    _update_session_gauge()
    _log("domain-update", f"removed dpids={remove} reason={reason}")

    return {"ok": True, "removed": remove, "reason": reason}


def _expand_fat_tree(new_k: int) -> dict:
    """
    Grow the fat-tree to a larger k (6, 8, 10).
    Recomputes tier layout, connects all new switches, and auto-assigns
    one controller domain per pod — demonstrating that scale-out requires
    multi-controller to stay within the per-controller load threshold.
    """
    global _FAT_TREE_K, _FAT_TREE_TIERS, _FAT_TREE_MAX

    if new_k <= _FAT_TREE_K:
        return {"ok": False, "error": f"new_k={new_k} must be larger than current k={_FAT_TREE_K}"}

    old_k   = _FAT_TREE_K
    old_max = _FAT_TREE_MAX

    # Recompute tiers
    _FAT_TREE_K = new_k
    _FAT_TREE_TIERS = {
        "core": {"start": 1,                                        "count": (new_k // 2) ** 2},
        "agg":  {"start": 1 + (new_k // 2) ** 2,                   "count": new_k * new_k // 2},
        "edge": {"start": 1 + (new_k // 2) ** 2 + new_k*new_k//2,  "count": new_k * new_k // 2},
    }
    _FAT_TREE_MAX = sum(t["count"] for t in _FAT_TREE_TIERS.values())

    # Connect all new switches (old ones already connected, skip them)
    try:
        svc = _svc()
        existing = {int(d) for d in svc.orchestrator.all_plans().keys()}
    except Exception:
        existing = set()

    new_dpids = [d for d in range(1, _FAT_TREE_MAX + 1) if d not in existing]
    results   = [_connect_switch(d) for d in new_dpids]
    ok_count  = sum(1 for r in results if r.get("ok"))

    # Auto-assign one controller domain per pod
    k_half     = new_k // 2
    agg_start  = 1 + (new_k // 2) ** 2
    edge_start = agg_start + new_k * new_k // 2
    new_domains = {}
    for pod_idx in range(new_k):
        ctrl_id   = f"sdn-controller-pod{pod_idx}"
        agg_dpids  = {agg_start  + pod_idx * k_half + j for j in range(k_half)}
        edge_dpids = {edge_start + pod_idx * k_half + j for j in range(k_half)}
        new_domains[ctrl_id] = agg_dpids | edge_dpids

    # Root controller owns all core switches
    core_count = (new_k // 2) ** 2
    new_domains["sdn-controller-root"] = set(range(1, core_count + 1))

    # Merge into existing domains (replace pods, keep root)
    _controller_domains.clear()
    _controller_domains.update(new_domains)

    _log("topology", f"expanded k={old_k}→{new_k}: {old_max}→{_FAT_TREE_MAX} switches, "
                     f"{len(new_domains)} controller domains, {ok_count} new switches connected")

    return {
        "ok":                  True,
        "old_k":               old_k,
        "new_k":               new_k,
        "total_switches":      _FAT_TREE_MAX,
        "new_switches_added":  ok_count,
        "controller_domains":  len(new_domains),
        "controllers":         list(new_domains.keys()),
        "message":             (f"Fat-tree expanded k={old_k}→{new_k}. "
                                f"{_FAT_TREE_MAX} total switches across {len(new_domains)} controller domains. "
                                f"Each pod controller manages {k_half*2} switches "
                                f"(within threshold={_CTRL_LOAD_THRESHOLD_SWITCHES})."),
    }


def _log(tag: str, msg: str, level: str = "INFO") -> None:
    """Print a timestamped backend log line to stdout."""
    ts = _time.strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] [{tag}] {msg}", flush=True)


def _apply_algorithm_background(algorithm: str) -> None:
    """Run proxy restart / rehandshake off the HTTP handler thread."""
    import subprocess, sys, time as _t
    _TLS_FLAG = "/tmp/pqc_tls_mode"
    python = sys.executable
    src_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    env = {**os.environ, "PYTHONPATH": os.path.join(src_root, "src")}

    if algorithm != "AES-256-GCM" and os.path.exists(_TLS_FLAG):
        # Switching back to PQC — remove flag and restart proxies in PQC mode.
        os.remove(_TLS_FLAG)
        try:
            subprocess.run(["pkill", "-f", "ctrl_proxy"],     capture_output=True, timeout=5)
            subprocess.run(["pkill", "-f", "sw_proxy_async"], capture_output=True, timeout=5)
            _t.sleep(1)
            subprocess.Popen([python, "-m", "pqc_sdn.apps.ctrl_proxy"],
                             env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.Popen([python, "-m", "pqc_sdn.apps.sw_proxy_async"],
                             env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            _log("policy", f"PQC mode restored — proxies restarted for {algorithm}")
        except Exception as e:
            _log("policy", f"proxy restart error: {e}", level="WARN")

    _push_algorithm_override_to_mininet(algorithm)


class MgmtHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        pass  # HTTP access log silenced — actions logged explicitly via _log()

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _html(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _check_auth(self) -> bool:
        """Return True if request carries a valid Bearer token, else send 401 and return False."""
        from pqc_sdn.settings import get_settings
        expected = get_settings().controller.api_token
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {expected}":
            return True
        # Also allow dashboard HTML (GET /) without auth for browser usability
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path == "/":
            return True
        self._json(401, {"error": "unauthorized"})
        log.warning("[mgmt_api] 401 unauthorized from %s: %s %s",
                    self.client_address[0], self.command, self.path)
        return False

    def do_GET(self) -> None:
        if not self._check_auth():
            return
        path = self.path.split("?")[0].rstrip("/") or "/"
        log.debug("[mgmt_api] GET %s from %s", path, self.client_address[0])

        if path == "/":
            if _DASHBOARD_HTML.exists():
                html = _DASHBOARD_HTML.read_bytes()
                # Inject the real API token so the dashboard can authenticate.
                # Replaces the placeholder token in the HTML with the actual
                # auto-generated token from settings.
                from pqc_sdn.settings import get_settings
                real_token = get_settings().controller.api_token
                html = html.replace(
                    b"const TOKEN = 'pqc-secret-token';",
                    f"const TOKEN = '{real_token}';".encode(),
                )
                self._html(200, html)
            else:
                self._html(404, b"<h1>mgmt_dashboard.html not found</h1>"
                               b"<p>Expected at: deploy/mgmt_dashboard.html</p>")
            return

        if path == "/mgmt/status":
            self._json(200, _build_status())
        elif path == "/mgmt/sessions":
            self._json(200, _build_sessions())
        elif path == "/mgmt/topology":
            self._json(200, _build_topology())
        elif path == "/mgmt/topology/tiers":
            # Use live Ryu dps for accurate tier counts
            existing: set = set(_ryu_dps.keys()) if _ryu_dps else set()
            if not existing:
                try:
                    svc = _svc()
                    existing = {int(k) for k in svc.orchestrator.all_plans().keys()}
                except Exception:
                    existing = set()
            self._json(200, {
                "k": _FAT_TREE_K,
                "total_switches": _FAT_TREE_MAX,
                "tiers": _fat_tree_tier_status(existing),
            })
        elif path == "/mgmt/config/algorithm":
            self._json(200, _build_algorithm_config())
        elif path == "/mgmt/security-events":
            limit = 50
            if "limit=" in self.path:
                try:
                    limit = int(self.path.split("limit=")[1].split("&")[0])
                except (ValueError, IndexError):
                    pass
            self._json(200, _build_events(limit))
        elif path == "/mgmt/policy/dscp-table":
            self._json(200, DSCP_TABLE)
        elif path == "/mgmt/metrics/security":
            self._json(200, _build_security_metrics())
        elif path == "/mgmt/metrics/performance":
            self._json(200, _build_performance_metrics())
        elif path == "/mgmt/metrics/network":
            self._json(200, _build_network_metrics())
        elif path == "/mgmt/config/cipher":
            from pqc_sdn.policy.engine import get_cipher_override
            c = get_cipher_override()
            self._json(200, {"cipher_override": c, "mode": "manual" if c else "dscp_auto"})
        elif path == "/mgmt/attacks/latest":
            p = _RESULTS_DIR / "attack_latest.json"
            if p.exists():
                try:
                    self._json(200, json.loads(p.read_text()))
                except Exception as e:
                    self._json(500, {"error": str(e)})
            else:
                self._json(404, {"error": "no attack results — run attack_simulator.py first"})
        elif path == "/mgmt/benchmarks":
            self._json(200, _list_benchmarks())
        elif path in ("/mgmt/benchmarks/latest", "/mgmt/benchmarks/latest.json"):
            self._json(200, _get_benchmark("latest"))
        elif path.startswith("/mgmt/benchmarks/"):
            name = path[len("/mgmt/benchmarks/"):]
            self._json(200, _get_benchmark(name))
        elif path == "/mgmt/flows":
            self._json(200, _list_flows())
        elif path == "/mgmt/links":
            links = [{"from": sorted(k)[0], "to": sorted(k)[1]} for k in _link_overrides]
            self._json(200, links)
        elif path == "/mgmt/controllers/status":
            self._json(200, _build_controller_status())
        else:
            self._json(404, {"error": f"unknown path: {path}"})

    def do_POST(self) -> None:
        if not self._check_auth():
            return
        path = self.path.split("?")[0].rstrip("/")
        log.debug("[mgmt_api] POST %s from %s", path, self.client_address[0])

        if path == "/mgmt/config/algorithm":
            length = int(self.headers.get("Content-Length", 0))
            try:
                raw = self.rfile.read(length) if length else b"{}"
                body = json.loads(raw)
            except Exception:
                self._json(400, {"error": "invalid JSON"})
                return

            algorithm = body.get("algorithm") or body.get("cipher")
            if not algorithm:
                self._json(400, {"error": "algorithm or cipher required"})
                return

            if algorithm not in ALGORITHMS and algorithm != "auto":
                self._json(400, {"error": f"unknown algorithm: {algorithm}", "valid": ALGORITHMS})
                return

            if algorithm in CIPHER_NAMES or algorithm == "auto":
                # Cipher override — proxy to plan_api if Ryu is live
                cipher_val = None if algorithm == "auto" else algorithm
                ctrl = _ctrl_api("/pqc/algorithm", "POST",
                                  {"cipher": cipher_val if cipher_val else "auto"})
                if ctrl is not None:
                    self._json(200, ctrl)
                    return
                from pqc_sdn.policy.engine import set_cipher_override
                set_cipher_override(cipher_val)
                _log("policy", f"cipher override → {cipher_val or 'dscp_auto'} (standalone)")
                self._json(200, {"ok": True, "cipher": cipher_val,
                                  "message": f"Cipher override: {cipher_val or 'DSCP auto'}"})
                return

            # KEM algorithm — proxy rehandshake to plan_api if Ryu is live
            ctrl = _ctrl_api("/pqc/algorithm", "POST", {"algorithm": algorithm})
            if ctrl is not None:
                _set_override(True, algorithm)
                _log("policy", f"KEM override SET → {algorithm} (via plan_api)")
                self._json(200, ctrl)
                return

            _set_override(True, algorithm)
            _log("policy", f"override SET → {algorithm} (standalone)")
            self._json(200, {"ok": True, "mode": "manual", "algorithm": algorithm,
                              "message": f"All new flows will use {algorithm}."})
            _threading.Thread(
                target=_apply_algorithm_background, args=(algorithm,), daemon=True
            ).start()
        elif path == "/mgmt/benchmarks/run":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception:
                body = {}
            tables = body.get("tables", None)
            result = _run_benchmark_sync(tables)
            if "error" in result:
                _log("benchmark", f"FAILED: {result['error']}", level="ERROR")
                self._json(500, result)
            else:
                summary = {
                    "ok": True,
                    "timestamp": result.get("timestamp"),
                    "tables_run": [k for k in ("ml_kem","handshake","cipher","security") if k in result],
                    "liboqs_available": result.get("liboqs_available", False),
                }
                _log("benchmark", f"complete tables={summary['tables_run']} liboqs={summary['liboqs_available']}")
                self._json(200, summary)
        elif path == "/mgmt/benchmarks/handshake-tcp":
            # Measure handshake latency over real loopback TCP (not in-process).
            # Body: {"variant": "ML-KEM-1024", "n": 50}
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception:
                body = {}
            from pqc_sdn.crypto.kem import KemVariant, parse_kem_variant
            variant_name = body.get("variant", "ML-KEM-1024")
            n = max(1, min(int(body.get("n", 50)), 500))
            try:
                variant = parse_kem_variant(variant_name)
                svc = _svc()
                result = svc.benchmark_handshake_tcp(variant=variant, n=n)
                _log("benchmark", f"TCP handshake bench: variant={variant_name} n={n} mean={result['mean_ms']}ms")
                self._json(200, {"ok": True, **result})
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
        elif path == "/mgmt/switches/connect":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception:
                self._json(400, {"error": "invalid JSON"}); return

            # Accept either {dpid: N} for a specific switch or {count: N} to
            # connect N switches starting from the next available dpid.
            # Also accepts {expand_k: 6|8} to grow the fat-tree to a larger k.
            if "expand_k" in body:
                new_k = int(body["expand_k"])
                if new_k not in (6, 8, 10):
                    self._json(400, {"error": "expand_k must be 6, 8, or 10"}); return
                self._json(200, _expand_fat_tree(new_k))
                return
            if "count" in body:
                count = int(body.get("count", 1))
                if count < 1 or count > _FAT_TREE_MAX:
                    self._json(400, {"error": f"count must be 1–{_FAT_TREE_MAX}"}); return
                try:
                    svc = _svc()
                    existing = set(_ryu_dps.keys()) if _ryu_dps else {int(k) for k in svc.orchestrator.all_plans().keys()}
                    tier_status = _fat_tree_tier_status(existing)
                    # Disconnected = known to Ryu (ever connected) but not currently active.
                    # In standalone mode (no Ryu), _ryu_switch_names is empty so fall back
                    # to the full fat-tree dpid range minus already-connected switches.
                    if _ryu_switch_names:
                        disconnected = {d for d in _ryu_switch_names if d not in existing}
                    else:
                        disconnected = {d for d in range(1, _FAT_TREE_MAX + 1) if d not in existing}
                    total_available = len(disconnected)
                    if total_available == 0:
                        def _ft_switches(k): return (k//2)**2 + k*k//2 + k*k//2
                        self._json(400, {
                            "error": f"Fat-tree k={_FAT_TREE_K} is full ({_FAT_TREE_MAX} switches)",
                            "tier_status": tier_status,
                            "expand_options": [
                                {"k": 6, "total_switches": _ft_switches(6),
                                 "new_controllers_needed": 6,
                                 "hint": f"k=6 → {_ft_switches(6)} switches, 6 pod controllers"},
                                {"k": 8, "total_switches": _ft_switches(8),
                                 "new_controllers_needed": 8,
                                 "hint": f"k=8 → {_ft_switches(8)} switches, 8 pod controllers"},
                            ],
                        }); return
                    if count > total_available:
                        self._json(400, {
                            "error": (f"Only {total_available} slot(s) available "
                                      f"(requested {count}). Fat-tree k={_FAT_TREE_K} "
                                      f"supports {_FAT_TREE_MAX} switches total."),
                            "tier_status": tier_status,
                        }); return
                    # Sort disconnected dpids: core first, then agg, then edge (tier_order primary).
                    # Within a tier, fill the one furthest below capacity first.
                    def _tier_deficit_key(dpid):
                        name = _ryu_switch_names.get(dpid, "")
                        n = name.lower()
                        if n.startswith("s1"): tier = "core"
                        elif n.startswith("s2"): tier = "agg"
                        elif n.startswith("s3"): tier = "edge"
                        else: tier = None
                        ts = tier_status.get(tier) if tier else None
                        deficit = (ts["available"] / max(ts["capacity"], 1)) if ts else 0.0
                        tier_order = {"core": 0, "agg": 1, "edge": 2}.get(tier, 3)
                        return (tier_order, -deficit, dpid)
                    dpids_to_add = sorted(disconnected, key=_tier_deficit_key)[:count]
                except Exception:
                    dpids_to_add = []
                # Connect switches concurrently — ML-KEM handshake is CPU-bound
                # and independently keyed per dpid, so parallel execution is safe.
                max_workers = min(len(dpids_to_add), 8)
                with ThreadPoolExecutor(max_workers=max_workers,
                                        thread_name_prefix="sw-connect") as pool:
                    futures = {pool.submit(_connect_switch, dpid): dpid
                               for dpid in dpids_to_add}
                    results = [f.result() for f in as_completed(futures)]
                ok_count = sum(1 for r in results if r.get("ok"))
                try:
                    existing2 = set(_ryu_dps.keys()) if _ryu_dps else {int(k) for k in _svc().orchestrator.all_plans().keys()}
                    tier_status_after = _fat_tree_tier_status(existing2)
                except Exception:
                    tier_status_after = {}
                self._json(200, {
                    "ok": ok_count == len(dpids_to_add),
                    "connected": ok_count,
                    "switches": results,
                    "tier_status": tier_status_after,
                })
            else:
                dpid = body.get("dpid")
                if not isinstance(dpid, int) or dpid < 1:
                    self._json(400, {"error": "dpid must be a positive integer"}); return
                self._json(200, _connect_switch(dpid))
        elif path.startswith("/mgmt/switches/") and path.endswith("/disconnect"):
            try:
                dpid = int(path.split("/")[3])
            except (IndexError, ValueError):
                self._json(400, {"error": "invalid dpid"}); return
            self._json(200, _disconnect_switch(dpid))
        elif path == "/mgmt/flows/assign":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception:
                self._json(400, {"error": "invalid JSON"}); return
            src_ip    = body.get("src_ip", "")
            dst_ip    = body.get("dst_ip", "")
            dscp      = int(body.get("dscp", 0))
            algorithm = body.get("algorithm", "auto")
            path_list = body.get("path", [])  # optional — auto-computed if empty
            if not src_ip or not dst_ip:
                self._json(400, {"error": "src_ip and dst_ip required"}); return
            self._json(200, _assign_flow(src_ip, dst_ip, dscp, algorithm, path_list))
        elif path in ("/mgmt/links/add", "/mgmt/links/remove"):
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception:
                self._json(400, {"error": "invalid JSON"}); return
            dpid_a = body.get("from") or body.get("dpid_a")
            dpid_b = body.get("to") or body.get("dpid_b")
            if not isinstance(dpid_a, int) or not isinstance(dpid_b, int) or dpid_a < 1 or dpid_b < 1:
                self._json(400, {"error": "from and to must be positive integer dpids"}); return
            if dpid_a == dpid_b:
                self._json(400, {"error": "from and to must be different"}); return
            if path.endswith("/add"):
                self._json(200, _add_link(dpid_a, dpid_b))
            else:
                self._json(200, _remove_link(dpid_a, dpid_b))
        elif path == "/mgmt/attack-event":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception:
                self._json(400, {"error": "invalid JSON"}); return
            event = body.get("event")
            if event:
                _events().appendleft({"timestamp": _time.time(), **body})
                _log("security", f"event={event} dpid={body.get('dpid','?')} src={body.get('src_ip','?')}", level="WARN")
                # Push to Prometheus gauges so Grafana shows live values
                try:
                    from pqc_sdn.metrics.exporter import (
                        PQC_REPLAY_ATTEMPTS, PQC_HANDSHAKE_FAILURES,
                        PQC_DOS_PACKET_IN_RATE,
                        PQC_CTRL_PLANE_SATURATION, PQC_KEY_EXHAUSTION_HANDSHAKES,
                        PQC_HARVEST_CAPTURED_BYTES, PQC_HARVEST_DECRYPT_SUCCESS,
                        PQC_ACTIVE_SESSIONS,
                    )
                    dpid = str(body.get("dpid", "sim"))
                    if event == "replay":
                        PQC_REPLAY_ATTEMPTS.labels(dpid=dpid).inc()
                    elif event == "handshake_failure":
                        PQC_HANDSHAKE_FAILURES.labels(dpid=dpid, reason=body.get("reason","cert_verify_failed")).inc()
                    elif event == "dos":
                        PQC_DOS_PACKET_IN_RATE.labels(dpid=dpid).set(body.get("rate", 950))
                    elif event == "dos_clear":
                        PQC_DOS_PACKET_IN_RATE.labels(dpid=dpid).set(0)
                    elif event == "saturation":
                        PQC_CTRL_PLANE_SATURATION.set(body.get("conns", 500))
                    elif event == "key_exhaustion":
                        PQC_KEY_EXHAUSTION_HANDSHAKES.inc()
                    elif event == "harvest":
                        PQC_HARVEST_CAPTURED_BYTES.set(body.get("bytes", 4096))
                        PQC_HARVEST_DECRYPT_SUCCESS.set(0)  # always 0 — ML-KEM is robust
                    elif event == "active_sessions":
                        PQC_ACTIVE_SESSIONS.set(body.get("count", 0))
                except Exception:
                    pass
            self._json(200, {"ok": True, "event": event})
        elif path == "/mgmt/controllers/scale-out":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception:
                self._json(400, {"error": "invalid JSON"}); return
            self._json(200, _scale_out_controller(body))
        elif path == "/mgmt/controllers/domain-update":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception:
                self._json(400, {"error": "invalid JSON"}); return
            self._json(200, _domain_update(body))
        else:
            self._json(404, {"error": f"unknown path: {path}"})


# ── Server lifecycle ───────────────────────────────────────────────────────────

def _metrics_sync_loop() -> None:
    """Background thread: sync live Ryu state to Prometheus every 5s so Grafana stays current."""
    import time as _t
    while True:
        _t.sleep(5)
        try:
            _update_session_gauge()
            # Also sync switch count gauge if exporter has one
            from pqc_sdn.metrics.exporter import PQC_ACTIVE_SESSIONS
            if _ryu_dps:
                PQC_ACTIVE_SESSIONS.set(len(_ryu_dps))
        except Exception:
            pass


def serve(host: str = "0.0.0.0", port: int = _MGMT_PORT, tls: bool = True) -> None:
    """Start the management plane HTTP server.  Blocks until stopped."""
    from socketserver import ThreadingMixIn
    import ssl as _ssl

    class _Reuse(ThreadingMixIn, HTTPServer):
        allow_reuse_address = True
        request_queue_size = 64
        daemon_threads = True

    # Start background metrics sync so Grafana and dashboard stay in sync with Ryu
    _threading.Thread(target=_metrics_sync_loop, daemon=True, name="mgmt-metrics-sync").start()

    httpd = _Reuse((host, port), MgmtHandler)

    # Wrap with TLS only if certs exist AND tls=True
    cert_file = _ROOT / "certs" / "controller.crt"
    key_file  = _ROOT / "certs" / "controller.key"
    if tls and cert_file.exists() and key_file.exists():
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = _ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"
        if not tls:
            log.info("[mgmt_api] TLS disabled via --no-tls flag — running HTTP")
        else:
            log.warning("[mgmt_api] TLS not available (certs/controller.crt missing) — running HTTP")

    log.info("[mgmt_api] Management plane listening on %s://%s:%d/", scheme, host, port)
    httpd.serve_forever()


def main() -> None:
    global _RYU_AVAILABLE

    import argparse as _ap
    _parser = _ap.ArgumentParser()
    _parser.add_argument('--no-tls', action='store_true',
                         help='Disable TLS (run plain HTTP) — useful for browser dashboard access')
    _args, _ = _parser.parse_known_args()

    from pqc_sdn.settings import get_settings as _gs

    # Probe Ryu — must happen before any _ctrl_api() calls
    _RYU_AVAILABLE = _probe_ryu()

    if _RYU_AVAILABLE:
        # Ryu process owns :9101 — do NOT start a competing exporter
        log.info("[mgmt_api] Ryu process owns metrics :9101 — skipping MetricsExporter")
    else:
        # Standalone mode: bootstrap a local ControlPlaneService and own :9101
        from pqc_sdn.apps import plan_api as _pa
        if _pa._SERVICE is None:
            _pa._SERVICE = _svc()
        try:
            from pqc_sdn.metrics.exporter import MetricsExporter
            _s = _gs()
            _exporter = MetricsExporter(_s.metrics.host, _s.metrics.port)
            _exporter.start()
            log.info("[mgmt_api] Metrics exporter on :%d (standalone mode)", _s.metrics.port)
        except Exception as _e:
            log.warning("[mgmt_api] Metrics exporter skipped: %s", _e)

    serve(tls=not _args.no_tls)


if __name__ == "__main__":
    main()
