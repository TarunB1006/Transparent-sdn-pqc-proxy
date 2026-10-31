"""Shared test fixtures."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_cipher_override(tmp_path, monkeypatch):
    """Point the cross-process cipher override at a per-test temp file and
    reset it afterwards, so no test leaks an override into another test (or
    into the real run/ directory used by a live stack)."""
    from pqc_sdn.policy import engine
    monkeypatch.setenv("PQC_OVERRIDE_FILE", str(tmp_path / "cipher_override"))
    monkeypatch.setattr(engine, "_cipher_override", None)
    monkeypatch.setattr(engine, "_override_cache", (-1.0, None))
    yield
    engine._cipher_override = None
    engine._override_cache = (-1.0, None)
