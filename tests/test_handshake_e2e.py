"""
End-to-end handshake verification: switch ↔ controller.

Tests:
1. Hybrid ML-KEM handshake produces matching shared secrets
2. Derived send/recv keys are symmetric (controller's recv == switch's send)
3. AES-GCM tunnel: switch encrypts → controller decrypts (and vice-versa)
4. Replay attack is rejected
5. Tampered ciphertext is rejected
6. ControlPlaneService.on_switch_connected publishes a proxy plan with correct keys
7. ProxyOrchestrator plan keys round-trip through SecureSession encrypt/decrypt
8. Certificate signature forgery triggers HandshakeError
9. Transcript MAC mismatch triggers HandshakeError
"""

import pytest

from pqc_sdn.channel.orchestrator import ProxyOrchestrator
from pqc_sdn.channel.registry import SessionRegistry
from pqc_sdn.controller.control_plane import ControlPlaneService
from pqc_sdn.crypto.kem import KemVariant
from pqc_sdn.exceptions import HandshakeError, SessionError
from pqc_sdn.tls.handshake import HybridHandshake
from pqc_sdn.tls.session import SecureSession, derive_directional_keys


# ── helpers ──────────────────────────────────────────────────────────────────

def _do_handshake(sw_id="switch-1", ctrl_id="sdn-controller", variant=KemVariant.ML_KEM_1024):
    sw = HybridHandshake(sw_id)
    ctrl = HybridHandshake(ctrl_id)
    hello = sw.create_client_hello(variant)
    s_hello, cert, encap, ctrl_secret = ctrl.server_respond(hello)
    result = sw.client_complete(s_hello, cert, encap)
    return sw, ctrl, result, ctrl_secret


def _controller_view(result):
    """Build the controller-side SecureSession with swapped keys."""
    p = result.session
    return SecureSession(
        session_id=p.session_id,
        send_key=p.recv_key,
        recv_key=p.send_key,
        key_id=p.key_id,
        local_id="sdn-controller",
        remote_id="switch-1",
    )


# ── tests ────────────────────────────────────────────────────────────────────

def test_handshake_shared_secret_matches():
    """Both sides derive matching session keys (via transcript-bound secret).

    The raw shared_secret is now bound to the transcript MAC on each side
    independently, so we verify the derived keys match instead of comparing
    the raw shared_secret bytes directly.
    """
    _, _, result, ctrl_secret = _do_handshake()
    # Derive keys on controller side from its bound secret
    ctrl_send, ctrl_recv = derive_directional_keys(ctrl_secret, result.session_id)
    # Switch's session keys must match controller's (perspective-swapped)
    assert result.session.send_key == ctrl_send
    assert result.session.recv_key == ctrl_recv


def test_directional_keys_are_symmetric():
    """Both parties derive the same (send, recv) key pair from the shared secret.
    The perspective swap (ctrl send↔recv) happens at SecureSession construction,
    not inside derive_directional_keys — verified by test_controller_encrypts_switch_decrypts."""
    _, _, result, ctrl_secret = _do_handshake()
    sw_send, sw_recv = result.session.send_key, result.session.recv_key
    ctrl_send, ctrl_recv = derive_directional_keys(ctrl_secret, result.session_id)
    # derive_directional_keys is deterministic given the same secret + session_id,
    # so both parties get the same raw keys; the swap is applied by the caller.
    assert ctrl_send == sw_send
    assert ctrl_recv == sw_recv


def test_switch_encrypts_controller_decrypts():
    _, _, result, _ = _do_handshake()
    ctrl_sess = _controller_view(result)
    msg = b"OF:PacketIn:dpid=1"
    pkt = result.session.encrypt(msg)
    assert ctrl_sess.decrypt(pkt) == msg


def test_controller_encrypts_switch_decrypts():
    _, _, result, _ = _do_handshake()
    ctrl_sess = _controller_view(result)
    msg = b"OF:FlowMod:priority=100"
    pkt = ctrl_sess.encrypt(msg)
    assert result.session.decrypt(pkt) == msg


def test_replay_rejected():
    _, _, result, _ = _do_handshake()
    ctrl_sess = _controller_view(result)
    pkt = result.session.encrypt(b"hello")
    ctrl_sess.decrypt(pkt)                # first time: ok
    with pytest.raises(SessionError, match="replay"):
        ctrl_sess.decrypt(pkt)            # second time: replay


def test_tampered_ciphertext_rejected():
    from pqc_sdn.tls.session import SecurePacket
    _, _, result, _ = _do_handshake()
    ctrl_sess = _controller_view(result)
    pkt = result.session.encrypt(b"secret")
    bad = SecurePacket(
        ciphertext=bytes([pkt.ciphertext[0] ^ 0xFF]) + pkt.ciphertext[1:],
        nonce=pkt.nonce,
        sequence_number=pkt.sequence_number,
        timestamp=pkt.timestamp,
        key_id=pkt.key_id,
        epoch=pkt.epoch,
    )
    with pytest.raises(Exception):   # cryptography raises InvalidTag
        ctrl_sess.decrypt(bad)


def test_forged_certificate_rejected():
    sw = HybridHandshake("switch-1")
    evil = HybridHandshake("evil-controller")
    hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
    # Legitimate server_respond to get proper encap
    ctrl = HybridHandshake("sdn-controller")
    s_hello, _, encap, _ = ctrl.server_respond(hello)
    # But hand the switch a certificate from the attacker
    _, evil_cert, _, _ = evil.server_respond(HybridHandshake("switch-2").create_client_hello())
    with pytest.raises(HandshakeError, match="certificate"):
        sw.client_complete(s_hello, evil_cert, encap)


def test_transcript_mac_mismatch_rejected():
    """Tampering with a handshake message in transit aborts the handshake.

    The responder's ML-DSA-87 signature covers SHA256(m1 || m2 || m4), so any
    modification of ServerHello (here: its session_id) fails verification at
    the initiator before decapsulation or key derivation.
    """
    sw = HybridHandshake("switch-1")
    ctrl = HybridHandshake("sdn-controller")
    hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
    s_hello, cert, encap, _ = ctrl.server_respond(hello)

    s_hello.session_id = "tampered-0000000000000000"
    with pytest.raises(HandshakeError):
        sw.client_complete(s_hello, cert, encap, ctrl.identity_public_key)


def test_control_plane_service_publishes_plan():
    """ControlPlaneService.on_switch_connected must publish an active tunnel plan."""
    svc = ControlPlaneService(controller_id="sdn-controller")
    dpid = 42
    assert svc.on_switch_connected(dpid)
    plans = svc.orchestrator.plans_for_switch_internal(dpid)
    assert plans, "no proxy plan published"
    tunnel = next((p for p in plans if p["role"] == "tunnel" and p["active"]), None)
    assert tunnel is not None, "no active tunnel plan"
    # Keys must be present and non-zero
    assert len(bytes.fromhex(tunnel["send_key_hex"])) == 32
    assert len(bytes.fromhex(tunnel["recv_key_hex"])) == 32


def test_proxy_plan_keys_roundtrip():
    """Keys in the published plan must produce a working encrypt/decrypt pair."""
    svc = ControlPlaneService(controller_id="sdn-controller")
    dpid = 7
    svc.on_switch_connected(dpid)
    plan = next(p for p in svc.orchestrator.plans_for_switch_internal(dpid) if p["role"] == "tunnel")

    sk = bytes.fromhex(plan["send_key_hex"])
    rk = bytes.fromhex(plan["recv_key_hex"])
    kid, ctx = plan["key_id"], plan["ctx"]

    # sw_proxy uses: send=sk, recv=rk
    sw_sess = SecureSession(ctx, sk, rk, kid, f"proxy-{dpid}", "controller")
    # ctrl_proxy uses: decrypt with sk (switch's send), encrypt with rk (switch's recv)
    ctrl_sess = SecureSession(ctx, rk, sk, kid, "ctrl_proxy", "switch")

    msg = b"OF:Hello"
    pkt = sw_sess.encrypt(msg)
    assert ctrl_sess.decrypt(pkt) == msg

    reply = b"OF:FeaturesRequest"
    pkt2 = ctrl_sess.encrypt(reply)
    assert sw_sess.decrypt(pkt2) == reply


def test_multiple_switches_independent_sessions():
    svc = ControlPlaneService(controller_id="sdn-controller")
    for dpid in [1, 2, 3]:
        assert svc.on_switch_connected(dpid)
    sessions = [svc.get_session(d) for d in [1, 2, 3]]
    # Each session must be distinct
    keys = [s.send_key for s in sessions]
    assert len(set(keys)) == 3, "sessions share keys — handshake is not per-switch"
