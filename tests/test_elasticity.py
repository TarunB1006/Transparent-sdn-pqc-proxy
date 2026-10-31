import tempfile
"""
Tests for the elasticity / CPU-triggered scale-out system.

Covers:
  - ScaleOutMonitor hysteresis (needs CPU_WINDOW consecutive high samples)
  - Candidate selection (tier priority, rate ordering, core exclusion)
  - _domain_update HTTP handler removes dpids from sessions + domains
  - _build_controller_status now includes cpu_threshold_pct
  - No scale-out when domain is empty
  - Cooldown prevents back-to-back scale-outs
"""
import json
import sys
import os
import time
import threading
import urllib.request

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqc_sdn.apps.elasticity import ScaleOutMonitor, CPU_THRESHOLD, CPU_WINDOW
from pqc_sdn.apps import mgmt_api
from pqc_sdn.apps import plan_api
from pqc_sdn.controller.control_plane import ControlPlaneService


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_monitor(domain_dpids, switch_names, packet_in_rates=None):
    return ScaleOutMonitor(
        pod_id=0,
        domain_dpids=set(domain_dpids),
        ryu_switch_names=switch_names,
        packet_in_rates=packet_in_rates or {},
        controller_domains={"sdn-controller": set(domain_dpids)},
        project_root="/tmp",
        venv_python=sys.executable,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Unit: hysteresis
# ─────────────────────────────────────────────────────────────────────────────

class TestHysteresis:
    def test_no_scaleout_below_window(self, monkeypatch):
        """Fewer than CPU_WINDOW high samples must not trigger scale-out."""
        triggered = []
        mon = _make_monitor({5, 13}, {5: "s201", 13: "s301"})
        monkeypatch.setattr(mon, "_trigger_scale_out", lambda cpu: triggered.append(cpu))
        monkeypatch.setattr(mon._proc, "cpu_percent", lambda interval=None: CPU_THRESHOLD + 1)
        mon._cooldown_end = 0

        for _ in range(CPU_WINDOW - 1):
            mon._tick()

        assert not triggered, "should not trigger before window is full"

    def test_scaleout_after_window(self, monkeypatch):
        """Exactly CPU_WINDOW consecutive high samples triggers scale-out once."""
        triggered = []
        mon = _make_monitor({5, 13}, {5: "s201", 13: "s301"})
        monkeypatch.setattr(mon, "_trigger_scale_out", lambda cpu: triggered.append(cpu))
        monkeypatch.setattr(mon._proc, "cpu_percent", lambda interval=None: CPU_THRESHOLD + 1)
        mon._cooldown_end = 0

        for _ in range(CPU_WINDOW):
            mon._tick()

        assert len(triggered) == 1

    def test_counter_resets_on_low_cpu(self, monkeypatch):
        """A low-CPU sample resets the consecutive counter."""
        triggered = []
        mon = _make_monitor({5, 13}, {5: "s201", 13: "s301"})
        monkeypatch.setattr(mon, "_trigger_scale_out", lambda cpu: triggered.append(cpu))
        mon._cooldown_end = 0

        cpus = iter([CPU_THRESHOLD + 1, CPU_THRESHOLD - 10, CPU_THRESHOLD + 1])
        monkeypatch.setattr(mon._proc, "cpu_percent",
                            lambda interval=None: next(cpus))

        for _ in range(3):
            mon._tick()

        assert not triggered

    def test_cooldown_blocks_second_trigger(self, monkeypatch):
        """Scale-out inside cooldown window is suppressed."""
        triggered = []
        mon = _make_monitor({5, 6, 13, 14}, {5: "s201", 6: "s202", 13: "s301", 14: "s302"})
        monkeypatch.setattr(mon, "_trigger_scale_out", lambda cpu: triggered.append(cpu))
        monkeypatch.setattr(mon._proc, "cpu_percent", lambda interval=None: CPU_THRESHOLD + 1)
        mon._cooldown_end = time.time() + 999  # active cooldown

        for _ in range(CPU_WINDOW + 2):
            mon._tick()

        assert not triggered


# ─────────────────────────────────────────────────────────────────────────────
# Unit: candidate selection
# ─────────────────────────────────────────────────────────────────────────────

class TestCandidateSelection:
    def test_core_switches_never_selected(self):
        """Core switches (s1xx) must not appear in candidates."""
        names = {1: "s101", 2: "s102", 5: "s201", 13: "s301"}
        mon = _make_monitor({1, 2, 5, 13}, names)
        candidates = mon._select_candidates()
        assert 1 not in candidates
        assert 2 not in candidates

    def test_edge_preferred_over_agg(self):
        """Edge (s3xx) switches should appear before agg (s2xx) switches."""
        names = {5: "s201", 6: "s202", 13: "s301", 14: "s302"}
        mon = _make_monitor({5, 6, 13, 14}, names)
        candidates = mon._select_candidates()
        # At least one edge switch must be in the first-half migration batch
        assert any(d in {13, 14} for d in candidates)

    def test_empty_domain_returns_no_candidates(self):
        mon = _make_monitor(set(), {})
        assert mon._select_candidates() == []

    def test_only_core_domain_returns_no_candidates(self):
        mon = _make_monitor({1, 2, 3, 4}, {1: "s101", 2: "s102", 3: "s103", 4: "s104"})
        assert mon._select_candidates() == []

    def test_takes_half_of_domain(self):
        names = {5: "s201", 6: "s202", 13: "s301", 14: "s302"}
        mon = _make_monitor({5, 6, 13, 14}, names)
        candidates = mon._select_candidates()
        assert len(candidates) == 2  # ceil(4 / 2) = 2

    def test_high_rate_switch_selected_first(self):
        """Switch with higher packet-in rate should be picked first."""
        names = {13: "s301", 14: "s302"}
        now = time.time()
        # dpid 14 has 10x the rate of dpid 13
        rates = {13: (10, now - 1), 14: (100, now - 1)}
        mon = _make_monitor({13, 14}, names, rates)
        candidates = mon._select_candidates()
        assert candidates[0] == 14


# ─────────────────────────────────────────────────────────────────────────────
# Unit: concurrent scale-out — global pod_id registry prevents port clash
# ─────────────────────────────────────────────────────────────────────────────

class TestConcurrentScaleOut:
    def setup_method(self):
        # Reset global registry before each test
        import pqc_sdn.apps.elasticity as e
        e._highest_pod_id = 0

    def test_two_monitors_get_different_pod_ids(self):
        """If pod0 and pod1 both trigger simultaneously they must get unique pod_ids."""
        from pqc_sdn.apps.elasticity import _alloc_pod_id, _register_pod_id
        _register_pod_id(0)
        _register_pod_id(1)

        ids = []
        barrier = threading.Barrier(2)

        def _trigger():
            barrier.wait()   # both goroutines hit alloc at the same time
            ids.append(_alloc_pod_id(tempfile.gettempdir()))

        threads = [threading.Thread(target=_trigger) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(set(ids)) == 2, f"pod_ids collided: {ids}"

    def test_three_concurrent_allocs_all_unique(self):
        from pqc_sdn.apps.elasticity import _alloc_pod_id
        ids = []
        barrier = threading.Barrier(3)

        def _go():
            barrier.wait()
            ids.append(_alloc_pod_id(tempfile.gettempdir()))

        threads = [threading.Thread(target=_go) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(set(ids)) == 3

    def test_pod1_monitor_does_not_reuse_pod0_id(self, monkeypatch):
        """
        Simulate pod0 already existing: pod1's first scale-out must not produce pod_id=1
        because pod0 already occupies it.
        """
        from pqc_sdn.apps import elasticity as e
        e._register_pod_id(0)   # root already taken
        e._register_pod_id(1)   # pod1 itself

        names = {13: "s301", 14: "s302", 15: "s303", 16: "s304"}
        spawned_with = {}

        def _fake_spawn(ctrl_id, pod_id, dpids):
            spawned_with["pod_id"] = pod_id
            return True

        mon = ScaleOutMonitor(
            pod_id=1,
            domain_dpids={13, 14, 15, 16},
            ryu_switch_names=names,
            packet_in_rates={},
            controller_domains={"sdn-controller-pod1": {13, 14, 15, 16}},
            project_root="/tmp",
            venv_python=sys.executable,
        )
        monkeypatch.setattr(mon, "_spawn_controller", _fake_spawn)
        monkeypatch.setattr(mon, "_spawn_proxies", lambda *a: [])
        monkeypatch.setattr(mon, "_redirect_switches_parallel", lambda *a: None)
        monkeypatch.setattr(mon, "_notify_old_controller", lambda *a: None)

        mon._trigger_scale_out(cpu=90.0)

        # New pod_id must be ≥ 2 (pod0=0, pod1=1 are both taken)
        assert spawned_with.get("pod_id", 0) >= 2


# ─────────────────────────────────────────────────────────────────────────────
# Unit: _domain_update handler
# ─────────────────────────────────────────────────────────────────────────────

class TestDomainUpdate:
    def setup_method(self):
        # Wire up a fresh service
        svc = ControlPlaneService("test-ctrl")
        svc.on_switch_connected(5)
        svc.on_switch_connected(13)
        plan_api._SERVICE = svc

        mgmt_api._controller_domains.clear()
        mgmt_api._controller_domains["test-ctrl"] = {5, 13}
        mgmt_api._ryu_dps.clear()
        mgmt_api._ryu_dps[5] = None
        mgmt_api._ryu_dps[13] = None

    def test_removes_dpids_from_domain(self):
        from pqc_sdn.apps.mgmt_api import _domain_update
        result = _domain_update({"remove_dpids": [5], "reason": "test"})
        assert result["ok"] is True
        assert 5 not in mgmt_api._controller_domains["test-ctrl"]
        assert 13 in mgmt_api._controller_domains["test-ctrl"]

    def test_removes_dpids_from_sessions(self):
        from pqc_sdn.apps.mgmt_api import _domain_update
        _domain_update({"remove_dpids": [5, 13], "reason": "test"})
        svc = plan_api._SERVICE
        assert 5 not in svc._switch_sessions
        assert 13 not in svc._switch_sessions

    def test_removes_dpids_from_ryu_dps(self):
        from pqc_sdn.apps.mgmt_api import _domain_update
        _domain_update({"remove_dpids": [5], "reason": "test"})
        assert 5 not in mgmt_api._ryu_dps
        assert 13 in mgmt_api._ryu_dps

    def test_empty_remove_returns_error(self):
        from pqc_sdn.apps.mgmt_api import _domain_update
        result = _domain_update({"remove_dpids": [], "reason": "test"})
        assert result["ok"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Unit: _build_controller_status includes CPU threshold
# ─────────────────────────────────────────────────────────────────────────────

class TestControllerStatus:
    def setup_method(self):
        svc = ControlPlaneService("root")
        plan_api._SERVICE = svc
        mgmt_api._controller_domains.clear()

    def test_cpu_threshold_in_status(self):
        from pqc_sdn.apps.mgmt_api import _build_controller_status
        status = _build_controller_status()
        assert "cpu_threshold_pct" in status
        assert status["cpu_threshold_pct"] == 85.0

    def test_overloaded_flag_set_when_cpu_high(self, monkeypatch):
        from pqc_sdn.apps.mgmt_api import _build_controller_status, _CTRL_LOAD_THRESHOLD_CPU_PCT
        monkeypatch.setattr(mgmt_api._PROC, "cpu_percent",
                            lambda interval=None: _CTRL_LOAD_THRESHOLD_CPU_PCT + 1)
        status = _build_controller_status()
        # single-controller path
        assert status["controllers"][0]["overloaded"] is True
