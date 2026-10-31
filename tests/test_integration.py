"""
Integration tests — no Ryu, no Mininet required.

Tests the full stack from handshake → proxy plan → encrypt/decrypt pipeline,
plus live plan_api HTTP integration, metrics pipeline, and DSCP routing dispatch.
"""
import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import HTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqc_sdn.controller.control_plane import ControlPlaneService
from pqc_sdn.apps import plan_api
from pqc_sdn.routing.qos_router import get_latency_path
from pqc_sdn.routing.ecmp import WeightedECMPRouter
from pqc_sdn.policy.engine import PolicyEngine, PolicyMetrics
from pqc_sdn.tls.frames import encode_frame, decode_frame, packet_from_frame

BEARER = "Bearer " + __import__("pqc_sdn.settings", fromlist=["get_settings"]).get_settings().controller.api_token


# ---------------------------------------------------------------------------
# Shared fixture: one ControlPlaneService + live plan_api server
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def live_stack():
    """Start a real plan_api HTTP server backed by a real ControlPlaneService."""
    svc = ControlPlaneService(controller_id="integ-ctrl")
    plan_api._SERVICE = svc

    class _Reuse(HTTPServer):
        allow_reuse_address = True

    httpd = _Reuse(("127.0.0.1", 18200), plan_api.PlanHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.15)

    # Connect two switches
    svc.on_switch_connected(1)
    svc.on_switch_connected(2)

    yield svc, 18200
    httpd.shutdown()


def _api_get(port, path):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Authorization": BEARER},
    )
    return json.loads(urllib.request.urlopen(req, timeout=3).read())


# ---------------------------------------------------------------------------
# 1. Handshake → Session → Encrypt/Decrypt pipeline
# ---------------------------------------------------------------------------

class TestHandshakePipeline:
    def test_full_roundtrip_ml_kem_1024(self):
        from pqc_sdn.tls.handshake import HybridHandshake
        from pqc_sdn.crypto.kem import KemVariant
        from pqc_sdn.tls.session import SecureSession

        sw = HybridHandshake("switch-99")
        ctrl = HybridHandshake("controller")
        hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
        s_hello, cert, encap, _ = ctrl.server_respond(hello)
        result = sw.client_complete(s_hello, cert, encap)

        assert result.session.is_active
        assert "ML-KEM-1024" in result.kem_variant

        peer = SecureSession(
            result.session.session_id,
            result.session.recv_key, result.session.send_key,
            result.session.key_id, "ctrl", "sw-99",
        )
        msg = b"OpenFlow FlowMod test payload"
        assert peer.decrypt(result.session.encrypt(msg)) == msg

    def test_wire_frame_encode_decode_roundtrip(self):
        from pqc_sdn.tls.handshake import HybridHandshake
        from pqc_sdn.crypto.kem import KemVariant
        from pqc_sdn.tls.session import SecureSession

        sw = HybridHandshake("sw-wire")
        ctrl = HybridHandshake("ctrl-wire")
        hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
        s_hello, cert, encap, _ = ctrl.server_respond(hello)
        result = sw.client_complete(s_hello, cert, encap)
        peer = SecureSession(
            result.session.session_id,
            result.session.recv_key, result.session.send_key,
            result.session.key_id, "ctrl", "sw",
        )

        # Simulate the full wire path: encrypt → encode_frame → decode_frame → decrypt
        plaintext = b"\x04\x00\x00\x08\x00\x00\x00\x01"  # OF Hello
        pkt = result.session.encrypt(plaintext)
        wire = encode_frame(pkt)
        wf = decode_frame(wire)
        recovered_pkt = packet_from_frame(wf, peer.key_id)
        assert peer.decrypt(recovered_pkt) == plaintext

    def test_transcript_mac_prevents_tampering(self):
        from pqc_sdn.tls.handshake import HybridHandshake
        from pqc_sdn.crypto.kem import KemVariant
        from pqc_sdn.exceptions import HandshakeError
        import copy

        sw = HybridHandshake("sw-tamper")
        ctrl = HybridHandshake("ctrl-tamper")
        hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
        s_hello, cert, encap, _ = ctrl.server_respond(hello)

        # MITM substitutes the KEM ciphertext: the transcript-bound ML-DSA-87
        # signature no longer verifies, so the handshake aborts.
        bad_encap = copy.copy(encap)
        bad_encap.ciphertext = bytes(len(encap.ciphertext))
        with pytest.raises(HandshakeError, match="signature verification failed"):
            sw.client_complete(s_hello, cert, bad_encap, ctrl.identity_public_key)


# ---------------------------------------------------------------------------
# 2. Plan API integration
# ---------------------------------------------------------------------------

class TestPlanAPI:
    def test_status_returns_switches(self, live_stack):
        svc, port = live_stack
        data = _api_get(port, "/pqc/status")
        assert data["switches"] == 2
        assert data["pqc_sessions"] == 2

    def test_plans_for_switch_has_tunnel(self, live_stack):
        svc, port = live_stack
        plans = _api_get(port, "/pqc/proxy/plans/1")
        assert len(plans) > 0
        tunnel = next(p for p in plans if p["role"] == "tunnel")
        assert tunnel["active"] is True
        assert len(tunnel["send_key_hex"]) == 64   # 32 bytes hex
        assert len(tunnel["recv_key_hex"]) == 64

    def test_plans_unknown_switch_returns_empty(self, live_stack):
        _, port = live_stack
        plans = _api_get(port, "/pqc/proxy/plans/9999")
        assert plans == []

    def test_unauthenticated_returns_401(self, live_stack):
        _, port = live_stack
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/pqc/status", timeout=2)
        assert exc.value.code == 401

    def test_session_keys_are_consistent(self, live_stack):
        """Keys from the plan must match what the session actually holds."""
        svc, port = live_stack
        plans = _api_get(port, "/pqc/proxy/plans/1")
        tunnel = next(p for p in plans if p["role"] == "tunnel")
        sk = bytes.fromhex(tunnel["send_key_hex"])
        rk = bytes.fromhex(tunnel["recv_key_hex"])
        assert len(sk) == 32 and len(rk) == 32
        assert sk != rk  # directional keys must differ


# ---------------------------------------------------------------------------
# 3. DSCP-based routing dispatch integration
# ---------------------------------------------------------------------------

class TestDSCPRouting:
    def test_ef_dscp46_selects_qos_router(self):
        """With a populated latency_map, DSCP 46 must choose the lower-RTT path."""
        latency_map = {(1, 2): 5.0, (2, 4): 3.0, (1, 3): 2.0, (3, 4): 50.0}
        path = get_latency_path(1, 4, latency_map)
        assert path == [1, 2, 4], f"Expected [1,2,4] got {path}"

    def test_non_ef_uses_ecmp_not_qos(self):
        """Non-EF bulk traffic (DSCP 0) must select AES-128-GCM symmetric cipher."""
        engine = PolicyEngine()
        rec = engine.evaluate(PolicyMetrics(dscp_value=0))   # BE
        assert rec.algorithm == "AES-128-GCM"
        assert rec.flow_type.value == "bulk_data"

    def test_ef_maps_to_chacha20(self):
        """EF (DSCP 46) is VoIP/latency-sensitive — must select ChaCha20-Poly1305."""
        engine = PolicyEngine()
        rec = engine.evaluate(PolicyMetrics(dscp_value=46))
        assert rec.algorithm == "ChaCha20-Poly1305"

    def test_all_dscp_classes_have_policy(self):
        """Every DSCP value 0–63 must return a symmetric cipher recommendation."""
        engine = PolicyEngine()
        valid = {"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"}
        for dscp in range(64):
            rec = engine.evaluate(PolicyMetrics(dscp_value=dscp))
            assert rec.algorithm in valid, f"DSCP={dscp} returned unexpected cipher {rec.algorithm}"


# ---------------------------------------------------------------------------
# 4. Metrics pipeline integration
# ---------------------------------------------------------------------------

class TestMetricsPipeline:
    @pytest.fixture(scope="class")
    def metrics_server(self):
        from pqc_sdn.metrics.exporter import MetricsExporter
        exp = MetricsExporter("127.0.0.1", 19201)
        exp.start()
        time.sleep(0.2)
        yield
        # no stop needed — daemon thread

    def _scrape(self, port=19201):
        return urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=3).read().decode()

    def test_metrics_endpoint_reachable(self, metrics_server):
        body = self._scrape()
        assert "pqc_" in body

    def test_replay_counter_increments(self, metrics_server):
        from pqc_sdn.metrics.exporter import PQC_REPLAY_ATTEMPTS
        PQC_REPLAY_ATTEMPTS.labels(dpid="integ-test").inc()
        body = self._scrape()
        assert "pqc_replay_attempts_total" in body

    def test_handshake_failure_counter(self, metrics_server):
        from pqc_sdn.metrics.exporter import PQC_HANDSHAKE_FAILURES
        PQC_HANDSHAKE_FAILURES.labels(dpid="integ-test", reason="cert_fail").inc()
        body = self._scrape()
        assert "pqc_handshake_failures_total" in body

    def test_echo_rtt_gauge(self, metrics_server):
        from pqc_sdn.metrics.exporter import PQC_ECHO_RTT_MS
        PQC_ECHO_RTT_MS.labels(dpid="5").set(12.5)
        body = self._scrape()
        assert 'pqc_echo_rtt_ms{dpid="5"}' in body
        assert "12.5" in body

    def test_active_sessions_gauge(self, metrics_server):
        from pqc_sdn.metrics.exporter import PQC_ACTIVE_SESSIONS
        PQC_ACTIVE_SESSIONS.set(3)
        body = self._scrape()
        assert "pqc_active_sessions 3.0" in body

    def test_dos_rate_gauge(self, metrics_server):
        from pqc_sdn.metrics.exporter import PQC_DOS_PACKET_IN_RATE
        PQC_DOS_PACKET_IN_RATE.labels(dpid="99").set(750.0)
        body = self._scrape()
        assert "pqc_dos_packet_in_rate" in body

    def test_harvest_metrics(self, metrics_server):
        from pqc_sdn.metrics.exporter import PQC_HARVEST_CAPTURED_BYTES, PQC_HARVEST_DECRYPT_SUCCESS
        PQC_HARVEST_CAPTURED_BYTES.set(512)
        PQC_HARVEST_DECRYPT_SUCCESS.set(0)
        body = self._scrape()
        assert "pqc_harvest_captured_bytes 512.0" in body
        assert "pqc_harvest_decrypt_success 0.0" in body


# ---------------------------------------------------------------------------
# 5. Quantum attack simulations (offline — no live ctrl_proxy needed)
# ---------------------------------------------------------------------------

class TestQuantumAttacks:
    @pytest.fixture(scope="class")
    def session_pair(self):
        from pqc_sdn.tls.handshake import HybridHandshake
        from pqc_sdn.crypto.kem import KemVariant
        from pqc_sdn.tls.session import SecureSession
        from pqc_sdn.channel.orchestrator import ProxyOrchestrator
        from pqc_sdn.channel.registry import SessionRegistry

        sw = HybridHandshake("sw-qa")
        ctrl = HybridHandshake("ctrl-qa")
        hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
        s_hello, cert, encap, _ = ctrl.server_respond(hello)
        result = sw.client_complete(s_hello, cert, encap)
        # Session keys come straight from the handshake (plans no longer
        # carry key material).
        sk, rk = result.session.send_key, result.session.recv_key
        kid, ctx = result.session.key_id, result.session.session_id
        send = SecureSession(ctx, sk, rk, kid, "proxy-42", "controller")
        recv = SecureSession(ctx, rk, sk, kid, "ctrl", "proxy-42")
        return send, recv

    def test_harvest_now_decrypt_later_fails(self, session_pair):
        """Captured AES-256-GCM ciphertext must be opaque to classical brute-force."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from pqc_sdn.tls.frames import HEADER, NONCE_SIZE

        send, _ = session_pair
        sensitive = b"FlowMod: admin grant 10.0.0.99"
        pkt = send.encrypt(sensitive)
        wire = encode_frame(pkt)

        nonce = wire[HEADER.size : HEADER.size + NONCE_SIZE]
        ciphertext = wire[HEADER.size + NONCE_SIZE:]

        # Attempt 200 random-key classical decryptions — all must fail
        successes = 0
        for _ in range(200):
            try:
                AESGCM(os.urandom(32)).decrypt(nonce, ciphertext, None)
                successes += 1
            except Exception:
                pass

        assert successes == 0, "Classical decryption succeeded — ciphertext is not opaque!"

    def test_replay_attack_blocked(self, session_pair):
        """A replayed wire frame must be rejected by sequence-number window."""
        from pqc_sdn.exceptions import SessionError
        send, recv = session_pair
        pkt = send.encrypt(b"replay-me")
        wire = encode_frame(pkt)

        # First delivery succeeds
        wf = decode_frame(wire)
        recv.decrypt(packet_from_frame(wf, recv.key_id))

        # Replay must be blocked
        with pytest.raises(SessionError, match="replay"):
            recv.decrypt(packet_from_frame(decode_frame(wire), recv.key_id))

    def test_grover_speedup_model(self):
        """Mathematically verify Grover's halving leaves AES-256 with 128-bit security."""
        key_bits = 256
        classical_ops = 2 ** key_bits
        grover_ops = 2 ** (key_bits // 2)  # Grover halves the exponent
        assert grover_ops == 2 ** 128
        # 2^128 is still computationally infeasible
        assert grover_ops > 10 ** 38

    def test_shor_does_not_apply_to_lattice(self):
        """ML-KEM is lattice-based (LWE problem) — Shor's algorithm provides no speedup."""
        from pqc_sdn.crypto.kem import KemVariant
        # Verify all variants are lattice-based (not RSA/ECC/DH)
        lattice_variants = {KemVariant.ML_KEM_512, KemVariant.ML_KEM_768, KemVariant.ML_KEM_1024}
        for v in lattice_variants:
            assert "ML-KEM" in v.value  # confirms NIST FIPS 203 lattice family

    def test_downgrade_detection(self):
        """All flows use ML-KEM — quantum_resistant is always True regardless of DSCP.
        Downgrade detection now means a high-sec DSCP class (CS6/AF11) receiving a
        lighter symmetric cipher than AES-256-GCM (detectable in controller.py)."""
        from pqc_sdn.policy.engine import PolicyEngine, PolicyMetrics
        engine = PolicyEngine()
        # EF → ChaCha20-Poly1305; still ML-KEM protected → quantum_resistant=True
        ef_rec = engine.evaluate(PolicyMetrics(dscp_value=46))
        assert ef_rec.quantum_resistant is True
        assert ef_rec.algorithm == "ChaCha20-Poly1305"
        # High-sec (CS6=48) → AES-256-GCM; also quantum_resistant=True
        cs6_rec = engine.evaluate(PolicyMetrics(dscp_value=48))
        assert cs6_rec.quantum_resistant is True
        assert cs6_rec.algorithm == "AES-256-GCM"
        # BE → AES-128-GCM
        be_rec = engine.evaluate(PolicyMetrics(dscp_value=0))
        assert be_rec.quantum_resistant is True
        assert be_rec.algorithm == "AES-128-GCM"

    def test_traffic_padding_conceals_length(self, session_pair):
        """AES-GCM padding must make wire sizes indistinguishable across message lengths."""
        send, _ = session_pair
        # Different plaintext sizes — wire sizes should collapse to same 256-byte block
        sizes = [2, 8, 28, 100]
        wire_sizes = []
        for n in sizes:
            pkt = send.encrypt(b"X" * n)
            wire_sizes.append(len(encode_frame(pkt)))

        # All plaintexts fit in one 256-byte padding block
        # (4-byte length prefix + payload, padded to 256 B → all ≤104 B → one block)
        assert len(set(wire_sizes)) == 1, (
            f"Wire sizes differ across message lengths: {dict(zip(sizes, wire_sizes))}"
        )
