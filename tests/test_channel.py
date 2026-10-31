"""Channel API tests."""

from pqc_sdn.channel.registry import pqc_decrypt, pqc_encrypt, get_registry
from pqc_sdn.crypto.kem import KemVariant
from pqc_sdn.tls.handshake import HybridHandshake


def test_pqc_encrypt_decrypt_api():
    sw = HybridHandshake("switch-2")
    ctl = HybridHandshake("sdn-controller")
    hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
    s_hello, cert, encap, _ = ctl.server_respond(hello)
    result = sw.client_complete(s_hello, cert, encap)

    reg = get_registry()
    ctx = "switch:2"
    reg.register(ctx, result.session, algorithm="ML-KEM-1024")
    peer_ctx = "switch:2:peer"
    reg.register(
        peer_ctx,
        type(result.session)(
            session_id=result.session.session_id,
            send_key=result.session.recv_key,
            recv_key=result.session.send_key,
            key_id=result.session.key_id,
            local_id="peer",
            remote_id="switch-2",
        ),
        algorithm="ML-KEM-1024",
    )

    pkt = pqc_encrypt(ctx, b"payload")
    assert pqc_decrypt(peer_ctx, pkt) == b"payload"
