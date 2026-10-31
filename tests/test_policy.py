"""DSCP policy engine tests."""

from pqc_sdn.policy.dscp import extract_dscp
from pqc_sdn.policy.engine import PolicyEngine, PolicyMetrics


def test_extract_dscp():
    assert extract_dscp(0xB8) == 46  # EF


def test_ef_recommends_chacha20():
    """EF (expedited forwarding) is latency-sensitive → ChaCha20-Poly1305."""
    engine = PolicyEngine()
    rec = engine.evaluate(PolicyMetrics(dscp_value=46))
    assert rec.algorithm == "ChaCha20-Poly1305"
    assert rec.flow_type.value == "latency_sensitive"


def test_be_recommends_aes128():
    """BE (best effort) is bulk traffic → AES-128-GCM."""
    engine = PolicyEngine()
    rec = engine.evaluate(PolicyMetrics(dscp_value=0))
    assert rec.algorithm == "AES-128-GCM"
    assert rec.flow_type.value == "bulk_data"


def test_cs6_recommends_aes256():
    """CS6 (control plane) is high-security → AES-256-GCM."""
    engine = PolicyEngine()
    rec = engine.evaluate(PolicyMetrics(dscp_value=48))
    assert rec.algorithm == "AES-256-GCM"
    assert rec.quantum_resistant is True


def test_kem_variant_is_global():
    """KEM variant is global (not per-flow) — all flows use the same KEM."""
    engine = PolicyEngine()
    ef = engine.evaluate(PolicyMetrics(dscp_value=46))
    be = engine.evaluate(PolicyMetrics(dscp_value=0))
    assert ef.kem_variant == be.kem_variant
