"""Unit tests for the adaptive cipher engine (monitor + selector).

The AdaptiveSelector manages symmetric cipher selection (ChaCha20-Poly1305
under load, DSCP auto when clear). It does NOT manage KEM variants —
KEM is fixed at deployment time.

All tests use a FakeMonitor so no psutil or real CPU sampling is needed.
"""

from __future__ import annotations

import time
import pytest

from pqc_sdn.adaptive.monitor import LoadMonitor
from pqc_sdn.adaptive.selector import AdaptiveSelector


# ── Helpers ────────────────────────────────────────────────────────────────────

class FakeMonitor:
    """Controllable stand-in for LoadMonitor — no background thread."""

    def __init__(self, cpu=0.0, latency_ms=0.0, queue_depth=0):
        self._cpu = cpu
        self._latency = latency_ms
        self._queue = queue_depth

    def set(self, cpu=None, latency_ms=None, queue_depth=None):
        if cpu is not None:
            self._cpu = cpu
        if latency_ms is not None:
            self._latency = latency_ms
        if queue_depth is not None:
            self._queue = queue_depth

    def snapshot(self):
        return {
            "cpu_percent": self._cpu,
            "latency_ms":  self._latency,
            "queue_depth": self._queue,
        }

    def start(self): pass
    def stop(self):  pass
    def notify_handshake_start(self): pass
    def notify_handshake_end(self, ms): pass


def make_selector(monitor, hold=0.0, **kwargs) -> AdaptiveSelector:
    defaults = dict(
        cpu_high_pct=85.0, cpu_low_pct=40.0,
        latency_high_ms=5.0, latency_low_ms=1.0,
        queue_depth_high=20, queue_depth_low=5,
        hold_seconds=hold,
    )
    defaults.update(kwargs)
    return AdaptiveSelector(monitor, **defaults)


# ── LoadMonitor tests ──────────────────────────────────────────────────────────

class TestLoadMonitor:
    def test_queue_increments_on_start(self):
        m = LoadMonitor()
        m.notify_handshake_start()
        m.notify_handshake_start()
        assert m.queue_depth == 2

    def test_queue_decrements_on_end(self):
        m = LoadMonitor()
        m.notify_handshake_start()
        m.notify_handshake_start()
        m.notify_handshake_end(10.0)
        assert m.queue_depth == 1

    def test_queue_never_goes_negative(self):
        m = LoadMonitor()
        m.notify_handshake_end(5.0)
        assert m.queue_depth == 0

    def test_ema_latency_updates(self):
        m = LoadMonitor()
        m.notify_handshake_start()
        m.notify_handshake_end(10.0)
        assert m.latency_ms == pytest.approx(10.0, abs=0.01)
        m.notify_handshake_start()
        m.notify_handshake_end(20.0)
        assert 10.0 < m.latency_ms < 20.0

    def test_snapshot_returns_all_fields(self):
        m = LoadMonitor()
        snap = m.snapshot()
        assert {"cpu_percent", "latency_ms", "queue_depth"} <= snap.keys()


# ── AdaptiveSelector tests ─────────────────────────────────────────────────────

class TestAdaptiveSelector:
    def test_starts_at_dscp_auto(self):
        """Initial state: no cipher override (DSCP-driven per-flow selection)."""
        sel = make_selector(FakeMonitor())
        assert sel.current_cipher is None  # None = DSCP auto

    def test_high_cpu_triggers_chacha20(self):
        """CPU above threshold → force ChaCha20-Poly1305 globally."""
        m = FakeMonitor(cpu=90.0)
        sel = make_selector(m)
        cipher, changed = sel.check()
        assert changed is True
        assert cipher == "ChaCha20-Poly1305"

    def test_high_latency_triggers_chacha20(self):
        """Handshake latency above threshold → force ChaCha20."""
        m = FakeMonitor(latency_ms=8.0)
        sel = make_selector(m)
        cipher, changed = sel.check()
        assert changed is True
        assert cipher == "ChaCha20-Poly1305"

    def test_high_queue_triggers_chacha20(self):
        """Queue depth above threshold → force ChaCha20."""
        m = FakeMonitor(queue_depth=25)
        sel = make_selector(m)
        cipher, changed = sel.check()
        assert changed is True
        assert cipher == "ChaCha20-Poly1305"

    def test_no_change_when_already_under_load(self):
        """If already in high-load mode, repeated checks don't re-trigger."""
        m = FakeMonitor(cpu=90.0)
        sel = make_selector(m)
        sel.check()  # first: triggers
        _, changed = sel.check()  # second: already in high-load
        assert changed is False

    def test_clear_returns_to_auto(self):
        """When all metrics drop below low thresholds → revert to DSCP auto."""
        m = FakeMonitor(cpu=90.0)
        sel = make_selector(m, hold=0.0)
        sel.check()  # enter high-load

        # Clear all metrics
        m.set(cpu=10.0, latency_ms=0.1, queue_depth=0)
        cipher, changed = sel.check()
        assert changed is True
        assert cipher is None  # back to DSCP auto

    def test_no_clear_if_only_cpu_drops(self):
        """All three metrics must be below low thresholds to clear."""
        m = FakeMonitor(cpu=90.0, latency_ms=8.0, queue_depth=25)
        sel = make_selector(m, hold=0.0)
        sel.check()  # enter high-load

        # Only CPU clears, latency and queue still high
        m.set(cpu=10.0)
        _, changed = sel.check()
        assert changed is False

    def test_hold_prevents_immediate_retransition(self):
        """During hold period, no transitions allowed."""
        m = FakeMonitor(cpu=90.0)
        sel = make_selector(m, hold=60.0)
        sel.check()  # triggers → enters hold

        # Metrics clear but hold is active → no change
        m.set(cpu=10.0, latency_ms=0.1, queue_depth=0)
        _, changed = sel.check()
        assert changed is False

    def test_state_contains_expected_keys(self):
        sel = make_selector(FakeMonitor())
        s = sel.state()
        assert {"cipher", "high_load", "reason", "cpu_pct",
                "latency_ms", "queue_depth", "in_hold"} <= s.keys()

    def test_last_reason_reflects_trigger(self):
        m = FakeMonitor(cpu=90.0)
        sel = make_selector(m)
        sel.check()
        assert "high-load" in sel.last_reason
        assert "cpu" in sel.last_reason
