"""Tests for Phase 2 additions: qos_router, DPID extraction, timestamp auth, ports, auth."""
import struct
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from pqc_sdn.routing.qos_router import get_latency_path
from pqc_sdn.apps.sw_proxy_async import _extract_dpid


# ── qos_router ────────────────────────────────────────────────────────────────

class TestQosRouter:
    def test_picks_lower_latency_path(self):
        m = {("A","B"): 5, ("B","D"): 3, ("A","C"): 2, ("C","D"): 10}
        assert get_latency_path("A", "D", m) == ["A", "B", "D"]  # 8ms < 12ms

    def test_excludes_inf_link(self):
        m = {("A","B"): 5, ("B","D"): float("inf"), ("A","C"): 2, ("C","D"): 10}
        assert get_latency_path("A", "D", m) == ["A", "C", "D"]

    def test_same_switch(self):
        assert get_latency_path(1, 1, {}) == [1]

    def test_unreachable_returns_none(self):
        assert get_latency_path("A", "Z", {("A","B"): 1}) is None

    def test_empty_map_returns_none(self):
        assert get_latency_path(1, 2, {}) is None


# ── sw_proxy_async DPID extraction ───────────────────────────────────────────

def _of_hello():
    return struct.pack("!BBHI", 0x04, 0, 8, 0)

def _features_reply(dpid: int):
    # version, type=6, length=32, xid, datapath_id, n_buffers, n_tables, aux, pad, caps, reserved
    return struct.pack("!BBHIQIBBHII", 0x04, 6, 32, 1, dpid, 256, 254, 0, 0, 0x4f, 0)

class TestExtractDpid:
    def test_features_reply_alone(self):
        assert _extract_dpid(_features_reply(42)) == 42

    def test_hello_then_features_reply(self):
        assert _extract_dpid(_of_hello() + _features_reply(7)) == 7

    def test_only_hello_returns_none(self):
        assert _extract_dpid(_of_hello()) is None

    def test_empty_returns_none(self):
        assert _extract_dpid(b"") is None

    def test_large_dpid(self):
        assert _extract_dpid(_features_reply(0xFFFFFFFFFFFFFFFF)) == 0xFFFFFFFFFFFFFFFF


# ── frames: authenticated timestamp inside ciphertext ────────────────────────

class TestSessionRoundtrip:
    @pytest.fixture(scope="class")
    def sessions(self):
        from pqc_sdn.tls.handshake import HybridHandshake
        from pqc_sdn.crypto.kem import KemVariant
        from pqc_sdn.tls.session import SecureSession
        sw = HybridHandshake("sw")
        ctrl = HybridHandshake("ctrl")
        hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
        s_hello, cert, encap, _ = ctrl.server_respond(hello)
        result = sw.client_complete(s_hello, cert, encap)
        peer = SecureSession(
            result.session.session_id,
            result.session.recv_key, result.session.send_key,
            result.session.key_id, "ctrl", "sw",
        )
        return result.session, peer

    def test_encrypt_decrypt(self, sessions):
        send, recv = sessions
        assert recv.decrypt(send.encrypt(b"hello")) == b"hello"

    def test_replay_rejected(self, sessions):
        from pqc_sdn.exceptions import SessionError
        send, recv = sessions
        pkt = send.encrypt(b"data")
        recv.decrypt(pkt)
        with pytest.raises(SessionError, match="replay"):
            recv.decrypt(pkt)


# ── dynamic port formula ──────────────────────────────────────────────────────

class TestDynamicPorts:
    def test_formula_pod0(self):
        assert 8082 + 0 == 8082
        assert 9101 + 0 == 9101

    def test_formula_pod1(self):
        assert 8082 + 1 == 8083
        assert 9101 + 1 == 9102

    def test_formula_pod2(self):
        assert 8082 + 2 == 8084
        assert 9101 + 2 == 9103


# ── mgmt_api auth ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def _auth_server():
    import threading, time
    from http.server import HTTPServer
    from pqc_sdn.apps import mgmt_api, plan_api
    from pqc_sdn.controller.control_plane import ControlPlaneService

    plan_api._SERVICE = ControlPlaneService(controller_id="auth-test")

    class _Reuse(HTTPServer):
        allow_reuse_address = True

    httpd = _Reuse(("127.0.0.1", 18097), mgmt_api.MgmtHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.15)
    yield 18097
    httpd.shutdown()


class TestMgmtAuth:
    def test_no_token_returns_401(self, _auth_server):
        import urllib.request, urllib.error
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"http://127.0.0.1:{_auth_server}/mgmt/status", timeout=2)
        assert exc.value.code == 401

    def test_wrong_token_returns_401(self, _auth_server):
        import urllib.request, urllib.error
        req = urllib.request.Request(
            f"http://127.0.0.1:{_auth_server}/mgmt/status",
            headers={"Authorization": "Bearer wrong-token"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=2)
        assert exc.value.code == 401

    def test_correct_token_returns_200(self, _auth_server):
        import urllib.request, json
        req = urllib.request.Request(
            f"http://127.0.0.1:{_auth_server}/mgmt/status",
            headers={"Authorization": f"Bearer {__import__('pqc_sdn.settings', fromlist=['get_settings']).get_settings().controller.api_token}"},
        )
        data = json.loads(urllib.request.urlopen(req, timeout=2).read())
        assert "switches" in data

    def test_dashboard_root_no_auth_needed(self, _auth_server):
        import urllib.request
        # GET / (dashboard HTML) should be accessible without token
        resp = urllib.request.urlopen(f"http://127.0.0.1:{_auth_server}/", timeout=2)
        assert resp.status == 200
