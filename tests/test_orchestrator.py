"""Proxy orchestrator tests."""

from pqc_sdn.channel.orchestrator import ProxyOrchestrator
from pqc_sdn.channel.registry import SessionRegistry
from pqc_sdn.crypto.kem import KemVariant
from pqc_sdn.tls.handshake import HybridHandshake


def test_control_plane_plan_published():
    sw = HybridHandshake("switch-3")
    ctl = HybridHandshake("sdn-controller")
    hello = sw.create_client_hello(KemVariant.ML_KEM_1024)
    s_hello, cert, encap, _ = ctl.server_respond(hello)
    result = sw.client_complete(s_hello, cert, encap)

    reg = SessionRegistry()
    orch = ProxyOrchestrator(reg)
    orch.activate_control_plane(3, result.session)

    plans = orch.plans_for_switch_internal(3)
    assert len(plans) == 1
    assert plans[0]["role"] == "tunnel"
    assert plans[0]["active"] is True
    assert len(plans[0]["send_key_hex"]) == 64
