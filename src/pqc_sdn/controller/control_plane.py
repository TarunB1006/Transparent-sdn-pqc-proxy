"""Control-plane PQC operations used by the SDN controller adapter."""

from __future__ import annotations

import logging
import threading
import time
from typing import List, Optional, Tuple

from pqc_sdn.channel.orchestrator import ProxyOrchestrator
from pqc_sdn.channel.registry import SessionRegistry
from pqc_sdn.crypto.kem import KemVariant
from pqc_sdn.kms.manager import KeyManager
from pqc_sdn.metrics.exporter import HANDSHAKE_SECONDS
from pqc_sdn.policy.engine import PolicyEngine, PolicyMetrics, set_adaptive_selector
from pqc_sdn.tls.handshake import HybridHandshake

log = logging.getLogger(__name__)


class ControlPlaneService:
    """
    Encapsulates handshake, session registry, proxy orchestration, and DSCP policy.
    Ryu (or another adapter) delegates to this service.
    """

    def __init__(
        self,
        controller_id: str = "sdn-controller",
        registry: Optional[SessionRegistry] = None,
        domain_dpids: Optional[set] = None,
    ) -> None:
        self.controller_id = controller_id
        self.registry = registry or SessionRegistry()
        self.orchestrator = ProxyOrchestrator(self.registry)
        self.kms = KeyManager()
        self.policy = PolicyEngine()
        self._controller_hs = HybridHandshake(controller_id)
        self._switch_sessions: dict[int, object] = {}
        self._switch_variants: dict[int, str] = {}
        self._sessions_lock = threading.Lock()
        self.domain_dpids: Optional[set] = domain_dpids

        # Adaptive engine — started only when adaptive.enabled is true
        self._monitor = None
        self._selector = None
        self._adaptive_watcher: Optional[threading.Thread] = None
        self._adaptive_running = False
        self._start_adaptive_if_enabled()

    # ── adaptive engine ────────────────────────────────────────────────────────

    def _start_adaptive_if_enabled(self) -> None:
        try:
            from pqc_sdn.settings import get_settings
            cfg = get_settings().adaptive
        except Exception:
            return
        if not cfg.enabled:
            return
        from pqc_sdn.adaptive.monitor import LoadMonitor
        from pqc_sdn.adaptive.selector import AdaptiveSelector
        self._monitor = LoadMonitor(poll_interval_seconds=cfg.poll_interval_seconds)
        self._selector = AdaptiveSelector(
            self._monitor,
            cpu_high_pct=cfg.cpu_high_pct,
            cpu_low_pct=cfg.cpu_low_pct,
            latency_high_ms=cfg.latency_high_ms,
            latency_low_ms=cfg.latency_low_ms,
            queue_depth_high=cfg.queue_depth_high,
            queue_depth_low=cfg.queue_depth_low,
            hold_seconds=cfg.hold_seconds,
        )
        set_adaptive_selector(self._selector)
        # Clear any override file left behind by a previous run.
        from pqc_sdn.policy.engine import set_cipher_override
        set_cipher_override(None)
        self._monitor.start()
        self._adaptive_running = True
        self._adaptive_watcher = threading.Thread(
            target=self._adaptive_watch_loop,
            args=(cfg.poll_interval_seconds,),
            daemon=True,
            name="pqc-adaptive-watcher",
        )
        self._adaptive_watcher.start()
        log.info("[adaptive] engine started (cpu_high=%.0f%% lat_high=%.0fms hold=%.0fs)",
                 cfg.cpu_high_pct, cfg.latency_high_ms, cfg.hold_seconds)

    def _adaptive_watch_loop(self, interval: float) -> None:
        """Periodically poll the selector and update the symmetric cipher override."""
        from pqc_sdn.policy.engine import set_cipher_override
        while self._adaptive_running:
            time.sleep(interval)
            if self._selector is None:
                continue
            try:
                cipher, changed = self._selector.check()
                if changed:
                    log.info("[adaptive] cipher override → %s",
                             cipher if cipher else "auto (DSCP)")
                    set_cipher_override(cipher)
            except Exception as exc:
                log.debug("[adaptive] watcher error: %s", exc)

    def stop_adaptive(self) -> None:
        self._adaptive_running = False
        if self._monitor:
            self._monitor.stop()

    def adaptive_state(self) -> Optional[dict]:
        if self._selector is None:
            return None
        return self._selector.state()

    # ── handshake ──────────────────────────────────────────────────────────────

    def on_switch_connected(self, dpid: int) -> bool:
        """Run ML-KEM handshake and activate control-plane proxy plan.

        If ctrl_proxy has already registered a real session (via the PQC\\x02
        handshake-first protocol), the in-process handshake is skipped so
        the dashboard keys stay consistent with the proxy's actual session keys.
        """
        if self.domain_dpids is not None and dpid not in self.domain_dpids:
            log.warning("dpid %d not in domain %s — ignoring", dpid, self.domain_dpids)
            return False

        with self._sessions_lock:
            if dpid in self._switch_sessions:
                log.info(
                    "on_switch_connected: dpid=%d session already registered by ctrl_proxy "
                    "— skipping in-process handshake",
                    dpid,
                )
                return True

        switch_id = f"switch-{dpid}"
        if self._monitor:
            self._monitor.notify_handshake_start()
        t0 = time.perf_counter()
        try:
            sw_hs = HybridHandshake(switch_id)
            # Read KEM variant from config (matches what the real proxy uses)
            from pqc_sdn.crypto.kem import parse_kem_variant as _parse_kem
            try:
                from pqc_sdn.settings import get_settings as _gs
                _kem_variant = _parse_kem(_gs().crypto.control_plane_kem)
            except Exception:
                _kem_variant = KemVariant.ML_KEM_512
            hello = sw_hs.create_client_hello(_kem_variant)
            ctrl_hs = HybridHandshake(self.controller_id)
            s_hello, cert, encap, _secret = ctrl_hs.server_respond(hello)
            result = sw_hs.client_complete(s_hello, cert, encap)
            elapsed = time.perf_counter() - t0
            if self._monitor:
                self._monitor.notify_handshake_end(elapsed * 1000)
            HANDSHAKE_SECONDS.labels(dpid=str(dpid), variant=result.kem_variant).observe(
                elapsed
            )
            with self._sessions_lock:
                self._switch_sessions[dpid] = result.session
                self._switch_variants[dpid] = result.kem_variant
            self.orchestrator.activate_control_plane(dpid, result.session)
            self.kms.control_plane(switch_id)
            log.info(
                "handshake ok sw-%d variant=%s time=%.1fms",
                dpid,
                result.kem_variant,
                elapsed * 1000,
            )
            return True
        except Exception as exc:
            if self._monitor:
                self._monitor.notify_handshake_end(0.0)
            log.error("handshake failed sw-%d: %s", dpid, exc, exc_info=True)
            return False

    def on_device_onboard(self, mac: str) -> dict:
        record = self.kms.onboarding(mac)
        return {
            "key_id": record.key_id,
            "variant": record.variant,
            "public_key": record.public_key.hex(),
        }

    def evaluate_flow(self, dscp_value: int) -> PolicyMetrics:
        return PolicyMetrics(dscp_value=dscp_value)

    def recommend(self, metrics: PolicyMetrics):
        return self.policy.evaluate(metrics)

    def on_flow_path(
        self,
        path: List[int],
        flow_key: Tuple,
        src_ip: str,
        dst_ip: str,
        dscp_value: int,
    ) -> str:
        rec = self.policy.evaluate(PolicyMetrics(dscp_value=dscp_value))
        self.orchestrator.activate_path(path, flow_key, rec.algorithm, dscp_value)
        return rec.algorithm

    def get_session(self, dpid: int):
        return self._switch_sessions.get(dpid)

    def disconnect(self, dpid: int) -> bool:
        """Remove a disconnected switch's session from all registries.

        Safe to call from any thread.  Returns False if dpid was not tracked.
        """
        with self._sessions_lock:
            if dpid not in self._switch_sessions:
                return False
            del self._switch_sessions[dpid]
            self._switch_variants.pop(dpid, None)

        with self.orchestrator._lock:
            self.orchestrator._plans.pop(dpid, None)

        try:
            from pqc_sdn.metrics.exporter import PQC_ACTIVE_SESSIONS
            PQC_ACTIVE_SESSIONS.set(len(self._switch_sessions))
        except Exception:
            pass

        log.info("disconnect: dpid=%d session removed", dpid)
        return True

    def rehandshake_all(self, algorithm: str) -> dict[int, dict]:
        """Re-run the full PQC handshake for all connected switches with a new KEM variant.

        Only call this for KEM variant changes (ML-KEM-512/768/1024) — e.g. threat
        escalation triggered by the operator.  Symmetric cipher changes do NOT require
        a rehandshake; use set_cipher_override() instead.
        """
        variant_map = {
            "ML-KEM-512":  KemVariant.ML_KEM_512,
            "ML-KEM-768":  KemVariant.ML_KEM_768,
            "ML-KEM-1024": KemVariant.ML_KEM_1024,
        }
        results = {}
        variant = variant_map.get(algorithm, KemVariant.ML_KEM_1024)
        for dpid in list(self._switch_sessions.keys()):
            switch_id = f"switch-{dpid}"
            t0 = time.perf_counter()
            try:
                sw_hs = HybridHandshake(switch_id)
                hello = sw_hs.create_client_hello(variant)
                ctrl_hs = HybridHandshake(self.controller_id)
                s_hello, cert, encap, _secret = ctrl_hs.server_respond(hello)
                result = sw_hs.client_complete(s_hello, cert, encap)
                elapsed = time.perf_counter() - t0
                HANDSHAKE_SECONDS.labels(dpid=str(dpid), variant=result.kem_variant).observe(elapsed)
                with self._sessions_lock:
                    self._switch_sessions[dpid] = result.session
                    self._switch_variants[dpid] = result.kem_variant
                self.orchestrator.activate_control_plane(dpid, result.session, algorithm=algorithm)
                results[dpid] = {"ok": True, "elapsed_ms": elapsed * 1000, "variant": result.kem_variant}
            except Exception as exc:
                log.error("rehandshake failed sw-%d: %s", dpid, exc)
                results[dpid] = {"ok": False, "elapsed_ms": 0.0, "variant": algorithm}
        return results

    def status(self) -> dict:
        base = {
            "network_status": "active" if self._switch_sessions else "no_switches",
            "switches": len(self._switch_sessions),
            "pqc_sessions": len(self._switch_sessions),
            "contexts": self.registry.active_count(),
        }
        adaptive = self.adaptive_state()
        if adaptive is not None:
            base["adaptive"] = adaptive
        return base

    def benchmark_handshake_tcp(self, variant: KemVariant = KemVariant.ML_KEM_1024,
                                 n: int = 50) -> dict:
        """Measure handshake latency over a real loopback TCP socket.

        This gives a realistic controller-switch overhead figure that includes
        serialization, syscall, and TCP round-trip costs — not just pure crypto.
        Each iteration:
          1. Server thread waits on accept()
          2. Client connects, sends serialized ClientHello
          3. Server reads, responds with ServerHello+Cert+EncapKey
          4. Client reads, completes handshake
          5. Both sides record wall-clock elapsed time

        Returns percentile stats in milliseconds.
        """
        import socket
        import statistics
        import struct as _struct

        samples = []

        def _server(srv_sock: socket.socket, results: list) -> None:
            try:
                conn, _ = srv_sock.accept()
                conn.settimeout(5.0)
                # Read length-prefixed ClientHello
                raw_len = conn.recv(4)
                if len(raw_len) < 4:
                    return
                msg_len = _struct.unpack("!I", raw_len)[0]
                data = b""
                while len(data) < msg_len:
                    chunk = conn.recv(msg_len - len(data))
                    if not chunk:
                        break
                    data += chunk
                hello = ClientHello.deserialize(data)

                ctrl = HybridHandshake("ctrl-bench")
                s_hello, cert, encap, _ = ctrl.server_respond(hello)

                # Send ServerHello + Cert + EncapKey as length-prefixed blobs
                for msg in (s_hello, cert, encap):
                    blob = msg.serialize()
                    conn.sendall(_struct.pack("!I", len(blob)) + blob)
                conn.close()
            except Exception:
                pass

        def _recv_msg(sock: socket.socket) -> bytes:
            raw_len = sock.recv(4)
            if len(raw_len) < 4:
                return b""
            msg_len = _struct.unpack("!I", raw_len)[0]
            data = b""
            while len(data) < msg_len:
                chunk = sock.recv(msg_len - len(data))
                if not chunk:
                    break
                data += chunk
            return data

        from pqc_sdn.tls.messages import ClientHello, ServerHello, Certificate, EncapsulatedKey

        for _ in range(n):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_srv:
                raw_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                raw_srv.bind(("127.0.0.1", 0))
                port = raw_srv.getsockname()[1]
                raw_srv.listen(1)

                srv_results: list = []
                srv_thread = threading.Thread(
                    target=_server, args=(raw_srv, srv_results), daemon=True
                )
                srv_thread.start()

                t0 = time.perf_counter()
                with socket.create_connection(("127.0.0.1", port), timeout=5) as cli:
                    sw = HybridHandshake("sw-bench")
                    hello = sw.create_client_hello(variant)
                    blob = hello.serialize()
                    cli.sendall(_struct.pack("!I", len(blob)) + blob)

                    sh_data   = _recv_msg(cli)
                    cert_data = _recv_msg(cli)
                    enc_data  = _recv_msg(cli)

                    s_hello = ServerHello.deserialize(sh_data)
                    cert    = Certificate.deserialize(cert_data)
                    encap   = EncapsulatedKey.deserialize(enc_data)
                    sw.client_complete(s_hello, cert, encap)

                elapsed_ms = (time.perf_counter() - t0) * 1000
                samples.append(elapsed_ms)
                srv_thread.join(timeout=2)

        sv = sorted(samples)
        return {
            "variant":    variant.value,
            "n":          n,
            "mean_ms":    round(statistics.mean(samples), 3),
            "median_ms":  round(statistics.median(samples), 3),
            "std_ms":     round(statistics.stdev(samples) if n > 1 else 0, 3),
            "p95_ms":     round(sv[int(0.95 * n) - 1], 3),
            "p99_ms":     round(sv[int(0.99 * n) - 1], 3),
            "min_ms":     round(sv[0], 3),
            "max_ms":     round(sv[-1], 3),
            "note":       "measured over loopback TCP — includes serialization + syscall overhead",
        }
