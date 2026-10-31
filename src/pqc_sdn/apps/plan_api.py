"""
plan_api.py — PQC-SDN Controller Northbound REST API (port 8080)

Runs inside the Ryu controller process. Exposes the full ControlPlaneService
state over HTTP(S) so that mgmt_api (a separate process) can delegate all
controller operations here rather than maintaining a disconnected local copy.

Also used by ctrl_proxy / sw_proxy_async to fetch per-switch session keys.

Endpoints
---------
GET  /pqc/status                       → svc.status() + security_events_total
GET  /pqc/proxy/plans/<dpid>           → per-switch proxy plans (used by proxies)
GET  /pqc/sessions                     → all active proxy plans
GET  /pqc/security-events?limit=N      → recent security events (max 200)
GET  /pqc/metrics/security             → security counters from event deque
GET  /pqc/metrics/performance          → handshake/packet-in latency + cpu/mem
GET  /pqc/metrics/network              → link utilization + encrypted bytes

POST /pqc/switches/connect             → on_switch_connected(dpid)
POST /pqc/switches/<dpid>/disconnect   → remove dpid from sessions + plans
POST /pqc/algorithm                    → rehandshake_all(algorithm) or set_cipher_override
POST /pqc/flows/assign                 → on_flow_path(...)
POST /pqc/benchmarks/handshake-tcp    → benchmark_handshake_tcp(variant, n)
POST /pqc/attack-event                 → record event + increment Prometheus counters
POST /pqc/benchmarks/run               → run crypto benchmark suite
"""

from __future__ import annotations

import collections
import importlib.util
import json
import os
import ssl
import time as _time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Optional

from pqc_sdn.controller.control_plane import ControlPlaneService
from pqc_sdn.logging_config import configure_logging, get_logger
from pqc_sdn.settings import get_settings

log = get_logger("pqc.plan_api")

# Shared service instance — set by controller.py: plan_api._SERVICE = self.service
_SERVICE: Optional[ControlPlaneService] = None

# Authoritative security event log (appendleft = newest first)
_security_events: collections.deque = collections.deque(maxlen=200)


def get_service() -> ControlPlaneService:
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = ControlPlaneService()
    return _SERVICE


# ── Metrics helpers (run in the Ryu process — reads the live registry) ────────

def _plan_security_metrics(svc: ControlPlaneService) -> dict:
    evts = list(_security_events)
    return {
        "replay_total":          sum(1 for e in evts if e.get("event") == "replay"),
        "rogue_switch_total":    sum(1 for e in evts if e.get("event") == "handshake_failure"),
        "dos_events":            sum(1 for e in evts if e.get("event") == "dos"),
        "saturation_events":     sum(1 for e in evts if e.get("event") == "saturation"),
        "key_exhaustion_total":  sum(1 for e in evts if e.get("event") == "key_exhaustion"),
        "harvest_events":        sum(1 for e in evts if e.get("event") == "harvest"),
        "active_sessions":       len(svc.orchestrator.all_plans()),
        "total_events":          len(evts),
    }


def _plan_performance_metrics() -> dict:
    import psutil
    proc = psutil.Process()
    cpu  = round(proc.cpu_percent(interval=None), 1)
    mem  = round(proc.memory_info().rss / 1024 / 1024, 1)
    hs_avg = pi_avg = 0.0
    try:
        from pqc_sdn.metrics.exporter import HANDSHAKE_SECONDS, PACKET_IN_SECONDS

        def _avg_ms(histogram) -> float:
            total_sum = sum(
                c._sum.get() for c in histogram._metrics.values()
            )
            total_count = sum(
                c._count.get() for c in histogram._metrics.values()
            )
            return round((total_sum / total_count) * 1000, 3) if total_count > 0 else 0.0

        hs_avg = _avg_ms(HANDSHAKE_SECONDS)
        pi_avg = _avg_ms(PACKET_IN_SECONDS)
    except Exception:
        pass
    return {
        "handshake_avg_ms": hs_avg,
        "packet_in_avg_ms": pi_avg,
        "cpu_percent":      cpu,
        "memory_mb":        mem,
        "source":           "live",
    }


def _plan_network_metrics(svc: ControlPlaneService) -> dict:
    link_util: dict = {}
    enc_bytes: dict = {}
    try:
        from pqc_sdn.metrics.exporter import LINK_UTILIZATION, PQC_ENCRYPTED_BYTES
        for labels, child in LINK_UTILIZATION._metrics.items():
            link_util[f"dpid={labels[0]},port={labels[1]}"] = round(
                float(child._value.get()) * 100, 1
            )
        for labels, child in PQC_ENCRYPTED_BYTES._metrics.items():
            enc_bytes[f"dpid={labels[0]}"] = int(child._value.get())
    except Exception:
        pass
    return {
        "connected_switches": len(svc.orchestrator.all_plans()),
        "active_sessions":    len(getattr(svc, "_switch_sessions", {})),
        "total_flows":        0,  # mgmt_api adds its _flow_assignments count on top
        "link_utilization":   link_util,
        "encrypted_bytes":    enc_bytes,
        "ryu_active":         True,
    }


# ── HTTP handler ──────────────────────────────────────────────────────────────

class PlanHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt: str, *args) -> None:
        log.debug(fmt, *args)

    def _json(self, code: int, payload: dict | list) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _check_auth(self) -> bool:
        expected = get_settings().controller.api_token
        if self.headers.get("Authorization") == f"Bearer {expected}":
            return True
        log.warning("[plan_api] 401 unauthorized from %s: %s %s",
                    self.client_address[0], self.command, self.path)
        self._json(401, {"error": "unauthorized"})
        return False

    def _read_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", 0))
        try:
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw) if raw else {}
        except Exception:
            self._json(400, {"error": "invalid JSON"})
            return None

    # ── GET ───────────────────────────────────────────────────────────────────

    def do_GET(self) -> None:
        if not self._check_auth():
            return
        svc  = get_service()
        path = self.path.split("?")[0]
        log.debug("[plan_api] GET %s from %s", path, self.client_address[0])

        if path == "/pqc/status":
            payload = svc.status()
            payload["security_events_total"] = len(_security_events)
            self._json(200, payload)

        elif path == "/pqc/sessions":
            self._json(200, svc.orchestrator.all_plans())

        elif path == "/pqc/security-events":
            limit = 200
            if "limit=" in self.path:
                try:
                    limit = int(self.path.split("limit=")[1].split("&")[0])
                except (ValueError, IndexError):
                    pass
            self._json(200, list(_security_events)[:limit])

        elif path == "/pqc/metrics/security":
            self._json(200, _plan_security_metrics(svc))

        elif path == "/pqc/metrics/performance":
            self._json(200, _plan_performance_metrics())

        elif path == "/pqc/metrics/network":
            self._json(200, _plan_network_metrics(svc))

        elif path.startswith("/pqc/proxy/plans/"):
            try:
                dpid = int(path[len("/pqc/proxy/plans/"):].strip("/"))
            except ValueError:
                self._json(400, {"error": "invalid dpid"})
                return
            self._json(200, svc.orchestrator.plans_for_switch_internal(dpid))

        else:
            self._json(404, {"error": "not found"})

    # ── POST ──────────────────────────────────────────────────────────────────

    def do_POST(self) -> None:
        if not self._check_auth():
            return
        body = self._read_body()
        if body is None:
            return
        svc  = get_service()
        path = self.path.split("?")[0]
        log.debug("[plan_api] POST %s from %s", path, self.client_address[0])

        if path == "/pqc/switches/connect":
            self._h_switch_connect(svc, body)
        elif path.startswith("/pqc/switches/") and path.endswith("/disconnect"):
            try:
                dpid = int(path.split("/")[3])
            except (IndexError, ValueError):
                self._json(400, {"error": "invalid dpid"})
                return
            self._h_switch_disconnect(svc, dpid)
        elif path == "/pqc/algorithm":
            self._h_algorithm(svc, body)
        elif path == "/pqc/flows/assign":
            self._h_flow_assign(svc, body)
        elif path == "/pqc/benchmarks/handshake-tcp":
            self._h_benchmark_tcp(svc, body)
        elif path == "/pqc/attack-event":
            self._h_attack_event(body)
        elif path == "/pqc/benchmarks/run":
            self._h_benchmark_run(body)
        elif path == "/pqc/sessions/register":
            self._h_session_register(svc, body)
        else:
            self._json(404, {"error": "not found"})

    # ── POST handlers ─────────────────────────────────────────────────────────

    def _h_switch_connect(self, svc: ControlPlaneService, body: dict) -> None:
        dpid = body.get("dpid")
        if not isinstance(dpid, int) or dpid < 1:
            self._json(400, {"error": "dpid must be a positive integer"})
            return
        t0 = _time.perf_counter()
        ok = svc.on_switch_connected(dpid)
        elapsed_ms = (_time.perf_counter() - t0) * 1000
        try:
            from pqc_sdn.metrics.exporter import PQC_ACTIVE_SESSIONS
            PQC_ACTIVE_SESSIONS.set(len(getattr(svc, "_switch_sessions", {})))
        except Exception:
            pass
        self._json(200, {
            "ok":          ok,
            "dpid":        dpid,
            "dpid_hex":    f"0x{dpid:04x}",
            "elapsed_ms":  round(elapsed_ms, 2),
            "message":     f"Switch {dpid} handshake {'ok' if ok else 'failed'}",
        })

    def _h_switch_disconnect(self, svc: ControlPlaneService, dpid: int) -> None:
        with svc._sessions_lock:
            removed = dpid in getattr(svc, "_switch_sessions", {})
            getattr(svc, "_switch_sessions", {}).pop(dpid, None)
            getattr(svc, "_switch_variants", {}).pop(dpid, None)
        svc.orchestrator._plans.pop(dpid, None)
        try:
            from pqc_sdn.metrics.exporter import PQC_ACTIVE_SESSIONS
            PQC_ACTIVE_SESSIONS.set(len(getattr(svc, "_switch_sessions", {})))
        except Exception:
            pass
        self._json(200, {"ok": True, "dpid": dpid, "removed": removed})

    def _h_algorithm(self, svc: ControlPlaneService, body: dict) -> None:
        CIPHER_NAMES = {"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"}
        KEM_NAMES    = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}

        cipher = body.get("cipher")
        algorithm = body.get("algorithm")

        if cipher is not None:
            # Symmetric cipher override (separate from KEM variant)
            from pqc_sdn.policy.engine import set_cipher_override
            if cipher == "auto" or cipher is None:
                set_cipher_override(None)
                self._json(200, {"ok": True, "cipher": None, "message": "Cipher override cleared (DSCP auto)"})
            elif cipher in CIPHER_NAMES:
                set_cipher_override(cipher)
                self._json(200, {"ok": True, "cipher": cipher,
                                  "message": f"All new flows will use {cipher}"})
            else:
                self._json(400, {"error": f"unknown cipher: {cipher}", "valid": sorted(CIPHER_NAMES)})
            return

        if algorithm is None:
            self._json(400, {"error": "algorithm or cipher required"})
            return

        if algorithm not in (KEM_NAMES | CIPHER_NAMES):
            self._json(400, {"error": f"unknown algorithm: {algorithm}",
                              "valid": sorted(KEM_NAMES | CIPHER_NAMES)})
            return

        if algorithm in CIPHER_NAMES:
            from pqc_sdn.policy.engine import set_cipher_override
            set_cipher_override(algorithm)
            self._json(200, {"ok": True, "cipher": algorithm,
                              "message": f"All new flows will use {algorithm}"})
            return

        # KEM rehandshake
        results = svc.rehandshake_all(algorithm)
        ok_count = sum(1 for v in results.values() if v.get("ok"))
        self._json(200, {
            "ok":                   True,
            "algorithm":            algorithm,
            "switches_rehandshaked": ok_count,
            "total":                len(results),
            "results":              {str(k): v for k, v in results.items()},
        })

    def _h_flow_assign(self, svc: ControlPlaneService, body: dict) -> None:
        src_ip    = body.get("src_ip", "")
        dst_ip    = body.get("dst_ip", "")
        dscp      = int(body.get("dscp", 0))
        path_list = body.get("path", [])
        algorithm = body.get("algorithm", "auto")
        if not src_ip or not dst_ip:
            self._json(400, {"error": "src_ip and dst_ip required"})
            return
        if not path_list:
            self._json(400, {"error": "path required (non-empty list of dpids)"})
            return
        flow_key = (src_ip, dst_ip, 0, 0)
        try:
            from pqc_sdn.policy.engine import set_algorithm_override, get_algorithm_override
            if algorithm and algorithm != "auto":
                prev = get_algorithm_override()
                set_algorithm_override(True, algorithm)
                algo_used = svc.on_flow_path(path_list, flow_key, src_ip, dst_ip, dscp)
                set_algorithm_override(*prev)
            else:
                algo_used = svc.on_flow_path(path_list, flow_key, src_ip, dst_ip, dscp)
            self._json(200, {
                "ok":        True,
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "dscp":      dscp,
                "algorithm": algo_used,
                "path":      path_list,
            })
        except Exception as e:
            self._json(500, {"ok": False, "error": str(e)})

    def _h_benchmark_tcp(self, svc: ControlPlaneService, body: dict) -> None:
        from pqc_sdn.crypto.kem import parse_kem_variant
        variant_name = body.get("variant", "ML-KEM-1024")
        n = max(1, min(int(body.get("n", 50)), 500))
        try:
            variant = parse_kem_variant(variant_name)
            result  = svc.benchmark_handshake_tcp(variant=variant, n=n)
            self._json(200, {"ok": True, **result})
        except Exception as e:
            self._json(500, {"ok": False, "error": str(e)})

    def _h_attack_event(self, body: dict) -> None:
        event = body.get("event")
        if event:
            _security_events.appendleft({"timestamp": _time.time(), **body})
            try:
                from pqc_sdn.metrics.exporter import (
                    PQC_REPLAY_ATTEMPTS, PQC_HANDSHAKE_FAILURES,
                    PQC_DOS_PACKET_IN_RATE, PQC_CTRL_PLANE_SATURATION,
                    PQC_KEY_EXHAUSTION_HANDSHAKES, PQC_HARVEST_CAPTURED_BYTES,
                    PQC_HARVEST_DECRYPT_SUCCESS, PQC_ACTIVE_SESSIONS,
                )
                dpid = str(body.get("dpid", "sim"))
                if event == "replay":
                    PQC_REPLAY_ATTEMPTS.labels(dpid=dpid).inc()
                elif event == "handshake_failure":
                    PQC_HANDSHAKE_FAILURES.labels(
                        dpid=dpid,
                        reason=body.get("reason", "cert_verify_failed"),
                    ).inc()
                elif event == "dos":
                    PQC_DOS_PACKET_IN_RATE.labels(dpid=dpid).set(body.get("rate", 950))
                elif event == "dos_clear":
                    PQC_DOS_PACKET_IN_RATE.labels(dpid=dpid).set(0)
                elif event == "saturation":
                    PQC_CTRL_PLANE_SATURATION.set(body.get("conns", 500))
                elif event == "key_exhaustion":
                    PQC_KEY_EXHAUSTION_HANDSHAKES.inc()
                elif event == "harvest":
                    PQC_HARVEST_CAPTURED_BYTES.set(body.get("bytes", 0))
                    PQC_HARVEST_DECRYPT_SUCCESS.set(body.get("cracked", 0))
                elif event == "active_sessions":
                    PQC_ACTIVE_SESSIONS.set(body.get("count", 0))
            except Exception:
                pass
        self._json(200, {"ok": True, "event": event})

    def _h_benchmark_run(self, body: dict) -> None:
        tables = body.get("tables", None)
        root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "..")
        )
        bench_path = os.path.join(root, "scripts", "benchmark.py")
        try:
            spec = importlib.util.spec_from_file_location("benchmark", bench_path)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            result = mod.run_all(n_kem=50, n_hs=30, n_cipher=200, n_sec=50,
                                 tables=tables)
            if "error" in result:
                self._json(500, result)
            else:
                self._json(200, {
                    "ok":              True,
                    "timestamp":       result.get("timestamp"),
                    "tables_run":      [k for k in ("ml_kem", "handshake", "cipher", "security")
                                        if k in result],
                    "liboqs_available": result.get("liboqs_available", False),
                })
        except Exception as e:
            self._json(500, {"error": str(e)})

    def _h_session_register(self, svc: ControlPlaneService, body: dict) -> None:
        """Register a session established by ctrl_proxy's real KEM handshake.

        Called by ctrl_proxy after the real ML-KEM exchange completes and the
        dpid has been resolved from the decrypted OF stream.  Updates the
        ControlPlaneService session registry so the dashboard shows live data.

        Security: Only metadata is transmitted — session keys NEVER leave
        the proxy process. The dashboard records the session existence and
        KEM variant but cannot decrypt traffic.
        """
        dpid            = body.get("dpid")
        session_id      = body.get("session_id", "")
        kem_variant     = body.get("kem_variant", "ML-KEM-512")
        key_id          = body.get("key_id", "")

        if not isinstance(dpid, int) or dpid < 1 or not session_id:
            self._json(400, {"error": "dpid (int) and session_id required"})
            return

        try:
            with svc._sessions_lock:
                # Record the session metadata for dashboard visibility.
                # No SecureSession is created — the controller doesn't need
                # the actual keys (ctrl_proxy handles all en/decryption).
                svc._switch_sessions[dpid] = session_id  # metadata only
                svc._switch_variants[dpid] = kem_variant
            try:
                from pqc_sdn.metrics.exporter import PQC_ACTIVE_SESSIONS, HANDSHAKE_SECONDS
                PQC_ACTIVE_SESSIONS.set(len(svc._switch_sessions))
                # Don't observe handshake duration — this session was registered
                # via API, not measured. Recording 0.0 would skew the histogram.
            except Exception:
                pass
            log.info("[plan_api] dpid=%d session registered (kem=%s key=%s) — metadata only, no keys transmitted",
                     dpid, kem_variant, key_id)
            self._json(200, {"ok": True, "dpid": dpid, "session_id": session_id})
        except Exception as exc:
            self._json(500, {"ok": False, "error": str(exc)})


# ── Server lifecycle ──────────────────────────────────────────────────────────

def _resolve(path: str) -> str:
    if os.path.isabs(path):
        return path
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    return os.path.join(root, path)


def serve(host: str, port: int) -> None:
    configure_logging()
    settings = get_settings()

    class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    httpd = _ThreadedHTTPServer((host, port), PlanHandler)

    cert = _resolve(settings.proxy.tls_cert)
    key  = _resolve(settings.proxy.tls_key)
    if os.path.exists(cert) and os.path.exists(key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        log.info("plan API https://%s:%d (TLS)", host, port)
    else:
        log.warning("TLS cert not found at %s — running HTTP (dev only)", cert)

    log.info("Northbound API http%s://%s:%d — ready",
             "s" if os.path.exists(cert) else "", host, port)
    httpd.serve_forever()


def main() -> None:
    settings = get_settings()
    serve("127.0.0.1", settings.proxy.controller_api_port)


if __name__ == "__main__":
    main()
