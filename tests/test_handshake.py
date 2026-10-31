"""Handshake and session round-trip tests."""

from pqc_sdn.crypto.kem import KemVariant
from pqc_sdn.tls.handshake import HybridHandshake


def test_hybrid_handshake_roundtrip():
    sw = HybridHandshake("switch-1")
    ctl = HybridHandshake("sdn-controller")

    hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
    s_hello, cert, encap, _ss = ctl.server_respond(hello)
    result = sw.client_complete(s_hello, cert, encap)

    assert result.session.is_active
    pkt = result.session.encrypt(b"openflow-test")
    # Peer uses reversed directional keys (controller side)
    peer = result.session
    controller_view = type(peer)(
        session_id=peer.session_id,
        send_key=peer.recv_key,
        recv_key=peer.send_key,
        key_id=peer.key_id,
        local_id="sdn-controller",
        remote_id="switch-1",
    )
    assert controller_view.decrypt(pkt) == b"openflow-test"
