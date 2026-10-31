"""DSCP-driven symmetric cipher policy engine.

Architecture (revised):
  - PQC KEM is FIXED per deployment tier (control plane: ML-KEM-1024 by
    default, see settings.crypto); an operator override re-handshakes all
    switches. Changing KEM requires a full
    re-handshake and is done infrequently at the operator level.
  - DSCP selects the SYMMETRIC cipher used to encrypt each OpenFlow frame.
    No handshake is needed to change cipher — it is applied per-frame.

  Mapping rationale:
    EF / AF4x / CS4  → ChaCha20-Poly1305   (VoIP, video: latency < 1ms, SW optimised)
    CS6 / CS7 / HIGH_SEC / AF11–13 (bank/DB) → AES-256-GCM (high-security, HW-AES)
    everything else  → AES-128-GCM          (balanced: faster than -256, still 128-bit)
"""

from __future__ import annotations

import os
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from pqc_sdn.policy.dscp import DscpClass, dscp_name


class FlowType(str, Enum):
    BULK = "bulk_data"
    VIDEO = "video_streaming"
    SIGNAL = "signalling"
    REALTIME = "real_time"
    CONTROL = "control_plane"
    HIGH_SEC = "high_security"
    LATENCY = "latency_sensitive"


@dataclass(frozen=True)
class PolicyMetrics:
    dscp_value: int = 0


@dataclass(frozen=True)
class PolicyRecommendation:
    algorithm: str          # symmetric cipher: ChaCha20-Poly1305 | AES-128-GCM | AES-256-GCM
    kem_variant: str        # PQC KEM (global default unless overridden)
    flow_type: FlowType
    quantum_resistant: bool
    security_bits: int
    estimated_overhead_ms: float
    dscp_value: int
    dscp_label: str
    reason: str


# DSCP → (flow_type, symmetric_cipher, reason)
# All flows use ML-KEM for key exchange; only the symmetric cipher varies.
_POLICY: Dict[DscpClass, Tuple[FlowType, str, str]] = {
    # High-security flows → AES-256-GCM (max confidentiality, HW-accelerated)
    DscpClass.CS6:     (FlowType.CONTROL,  "AES-256-GCM",        "control plane"),
    DscpClass.CS7:     (FlowType.CONTROL,  "AES-256-GCM",        "control plane"),
    DscpClass.HIGH_SEC:(FlowType.HIGH_SEC, "AES-256-GCM",        "high security"),
    DscpClass.AF11:    (FlowType.HIGH_SEC, "AES-256-GCM",        "bank/DB AF11"),
    DscpClass.AF12:    (FlowType.HIGH_SEC, "AES-256-GCM",        "bank/DB AF12"),
    DscpClass.AF13:    (FlowType.HIGH_SEC, "AES-256-GCM",        "bank/DB AF13"),

    # Latency-sensitive flows → ChaCha20-Poly1305 (software-optimised, no AES-NI needed)
    DscpClass.EF:      (FlowType.LATENCY,  "ChaCha20-Poly1305",  "VoIP/expedited forwarding"),
    DscpClass.CS4:     (FlowType.REALTIME, "ChaCha20-Poly1305",  "real-time CS4"),
    DscpClass.AF41:    (FlowType.REALTIME, "ChaCha20-Poly1305",  "real-time AF4"),
    DscpClass.AF42:    (FlowType.REALTIME, "ChaCha20-Poly1305",  "real-time AF4"),
    DscpClass.AF43:    (FlowType.REALTIME, "ChaCha20-Poly1305",  "real-time AF4"),

    # Everything else → AES-128-GCM (balanced: 128-bit security, faster than -256)
    DscpClass.BE:      (FlowType.BULK,     "AES-128-GCM",        "best effort bulk"),
    DscpClass.AF21:    (FlowType.VIDEO,    "AES-128-GCM",        "video AF2"),
    DscpClass.AF22:    (FlowType.VIDEO,    "AES-128-GCM",        "video AF2"),
    DscpClass.AF23:    (FlowType.VIDEO,    "AES-128-GCM",        "video AF2"),
    DscpClass.CS3:     (FlowType.VIDEO,    "AES-128-GCM",        "broadcast video"),
    DscpClass.AF31:    (FlowType.SIGNAL,   "AES-128-GCM",        "signalling AF3"),
    DscpClass.AF32:    (FlowType.SIGNAL,   "AES-128-GCM",        "signalling AF3"),
    DscpClass.AF33:    (FlowType.SIGNAL,   "AES-128-GCM",        "signalling AF3"),
    DscpClass.CS5:     (FlowType.SIGNAL,   "AES-128-GCM",        "signalling CS5"),
}

# Overhead/security properties for each symmetric cipher
CIPHER_METRICS: Dict[str, Tuple[int, float]] = {
    # (security_bits, estimated_overhead_ms)
    "AES-256-GCM":       (256, 0.18),
    "AES-128-GCM":       (128, 0.12),
    "ChaCha20-Poly1305": (256, 0.09),   # 256-bit key; fastest on non-AES-NI hardware
}

# Global PQC KEM override (default ML-KEM-512; operator may elevate to 768/1024)
_override_enabled: bool = False
_override_algorithm: str = "ML-KEM-512"   # PQC KEM variant, NOT symmetric cipher

# Symmetric cipher override — when set, ALL new flows use this cipher regardless of DSCP.
# None = auto (DSCP-driven). Set via mgmt API "symmetric cipher" buttons.
_cipher_override: Optional[str] = None

# Adaptive engine reference — set by ControlPlaneService when adaptive.enabled
_adaptive_selector = None  # type: Optional[Any]


def get_algorithm_override() -> tuple[bool, str]:
    return _override_enabled, _override_algorithm


def set_algorithm_override(enabled: bool, algorithm: str = "ML-KEM-1024") -> None:
    """Override the global PQC KEM variant (e.g. during threat escalation).
    Defaults to ML-KEM-1024 (maximum security) so a bare enable=True call
    always escalates to the strongest KEM, never silently weakens it."""
    global _override_enabled, _override_algorithm
    _override_enabled = enabled
    _override_algorithm = algorithm


# The override is set in the controller process (adaptive selector, mgmt API)
# but consumed in the separate switch/controller proxy processes, so it is
# published through a small file. Readers re-check it at most every
# _OVERRIDE_POLL_S seconds, keeping the per-frame cost to a clock read.
_OVERRIDE_POLL_S = 0.5
_override_cache: Tuple[float, Optional[str]] = (-1.0, None)


def _override_file() -> str:
    env = os.environ.get("PQC_OVERRIDE_FILE")
    if env:
        return env
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    return os.path.join(root, "run", "cipher_override")


def set_cipher_override(cipher: Optional[str]) -> None:
    """Set or clear the global symmetric cipher override.
    cipher: 'AES-256-GCM' | 'AES-128-GCM' | 'ChaCha20-Poly1305' | None (auto).
    """
    global _cipher_override, _override_cache
    valid = {"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305", None}
    if cipher not in valid:
        raise ValueError(f"Unknown cipher: {cipher}. Valid: {valid}")
    _cipher_override = cipher
    _override_cache = (time.monotonic(), cipher)
    path = _override_file()
    try:
        if cipher is None:
            if os.path.exists(path):
                os.remove(path)
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "w") as fh:
                fh.write(cipher)
            os.replace(tmp, path)   # atomic publish
    except OSError:
        pass


def get_cipher_override() -> Optional[str]:
    global _override_cache
    now = time.monotonic()
    checked_at, value = _override_cache
    if now - checked_at < _OVERRIDE_POLL_S:
        return value
    try:
        with open(_override_file()) as fh:
            value = fh.read().strip() or None
    except OSError:
        value = None
    if value not in (None, "AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"):
        value = None
    _override_cache = (now, value)
    return value


def set_adaptive_selector(selector) -> None:
    """Register the AdaptiveSelector instance (called by ControlPlaneService)."""
    global _adaptive_selector
    _adaptive_selector = selector


def get_kem_variant() -> str:
    """Return the active PQC KEM variant.

    Priority:
      1. Manual override (operator-set via mgmt API threat escalation)
      2. Deployment-time setting (settings.crypto.control_plane_kem)
      3. Fallback: ML-KEM-1024 (maximum security when settings unavailable)

    The adaptive engine selects the symmetric cipher, not the KEM.
    KEM is a one-time handshake cost fixed at deployment time.
    """
    if _override_enabled:
        return _override_algorithm
    try:
        from pqc_sdn.settings import get_settings
        return get_settings().crypto.control_plane_kem
    except Exception:
        return "ML-KEM-1024"


class PolicyEngine:
    """Evaluate DSCP and return symmetric cipher recommendation.

    The PQC KEM is fixed globally (ML-KEM-512 default); only the symmetric
    cipher changes per flow based on DSCP class.

    DSCP integrity: tracks the initial DSCP per flow key. If a subsequent
    evaluation shows the DSCP has changed to a weaker cipher class, the
    original (stronger) cipher is enforced and a downgrade event is logged.
    This mitigates DSCP field manipulation by compromised switches.
    """

    # Cipher strength ranking — higher is stronger
    _CIPHER_RANK = {"AES-256-GCM": 3, "ChaCha20-Poly1305": 2, "AES-128-GCM": 1}

    # Bound on tracked flows; least-recently-seen flows are evicted first.
    MAX_TRACKED_FLOWS = 65536
    # At most one downgrade log line per interval (events are still counted).
    DOWNGRADE_LOG_INTERVAL_S = 1.0

    def __init__(self):
        # Track initial DSCP → cipher assignment per flow_key
        # Key: flow identifier (set by caller via evaluate_flow), Value: (dscp, cipher)
        self._flow_dscp_baseline: "OrderedDict[str, Tuple[int, str]]" = OrderedDict()
        self._downgrade_events: int = 0
        self._last_downgrade_log: float = float("-inf")

    def register_flow(self, flow_key: str, dscp_value: int) -> None:
        """Record the initial DSCP for a flow. Called at flow creation."""
        rec = self.evaluate(PolicyMetrics(dscp_value=dscp_value), apply_override=False)
        self._flow_dscp_baseline[flow_key] = (dscp_value, rec.algorithm)
        if len(self._flow_dscp_baseline) > self.MAX_TRACKED_FLOWS:
            self._flow_dscp_baseline.popitem(last=False)

    def select_cipher(self, flow_key: str, dscp_value: int) -> Tuple[str, bool]:
        """Per-frame entry point used by the proxies.

        Registers the flow on first sight, enforces the original cipher if a
        later packet's DSCP maps to a weaker one, then applies the global
        override (if any). Returns (cipher, downgrade_detected).
        """
        if flow_key in self._flow_dscp_baseline:
            self._flow_dscp_baseline.move_to_end(flow_key)
            before = self._downgrade_events
            cipher = self.check_dscp_integrity(flow_key, dscp_value)
            downgraded = self._downgrade_events != before
        else:
            self.register_flow(flow_key, dscp_value)
            cipher = self._flow_dscp_baseline[flow_key][1]
            downgraded = False
        override = get_cipher_override()
        return (override or cipher), downgraded

    def check_dscp_integrity(self, flow_key: str, current_dscp: int) -> Optional[str]:
        """Check if a flow's DSCP has been tampered to a weaker cipher.

        Returns the enforced cipher (original if downgraded, current if OK),
        or None if the flow isn't tracked.
        """
        baseline = self._flow_dscp_baseline.get(flow_key)
        if baseline is None:
            return None

        original_dscp, original_cipher = baseline
        if current_dscp == original_dscp:
            return original_cipher  # no change

        # DSCP changed — check if the new cipher is weaker
        new_rec = self.evaluate(PolicyMetrics(dscp_value=current_dscp), apply_override=False)
        new_cipher = new_rec.algorithm

        orig_rank = self._CIPHER_RANK.get(original_cipher, 0)
        new_rank = self._CIPHER_RANK.get(new_cipher, 0)

        if new_rank < orig_rank:
            # Downgrade detected — enforce the original stronger cipher
            self._downgrade_events += 1
            try:
                from pqc_sdn.metrics.exporter import PQC_DOWNGRADE_ATTEMPTS
                PQC_DOWNGRADE_ATTEMPTS.labels(src_ip="policy", dst_ip="dscp").inc()  # constant labels: bounded cardinality
            except Exception:
                pass
            # Rate-limited: an attacker who flips DSCP values must not be able
            # to flood the log. The counter above stays exact.
            now = time.monotonic()
            if now - self._last_downgrade_log >= self.DOWNGRADE_LOG_INTERVAL_S:
                import logging
                logging.getLogger(__name__).warning(
                    "[SECURITY] DSCP downgrade detected for flow %s: "
                    "DSCP %d→%d, cipher %s→%s — enforcing original %s "
                    "(%d downgrade events in total)",
                    flow_key, original_dscp, current_dscp,
                    original_cipher, new_cipher, original_cipher, self._downgrade_events,
                )
                self._last_downgrade_log = now
            return original_cipher  # enforce the stronger cipher

        return new_cipher  # upgrade or lateral move is OK

    @property
    def downgrade_events(self) -> int:
        return self._downgrade_events

    def evaluate(self, metrics: PolicyMetrics, apply_override: bool = True) -> PolicyRecommendation:
        dscp_class = DscpClass.from_value(metrics.dscp_value)
        if dscp_class in _POLICY:
            flow_type, cipher, reason = _POLICY[dscp_class]
        else:
            flow_type, cipher, reason = (
                FlowType.BULK,
                "AES-128-GCM",
                f"unknown DSCP {metrics.dscp_value} — default",
            )
        # Symmetric cipher override: operator forces all flows to a single cipher
        override = get_cipher_override() if apply_override else None
        if override is not None:
            cipher = override
        bits, overhead = CIPHER_METRICS.get(cipher, (128, 0.15))
        return PolicyRecommendation(
            algorithm=cipher,
            kem_variant=get_kem_variant(),
            flow_type=flow_type,
            quantum_resistant=True,   # all flows use ML-KEM; cipher choice doesn't change this
            security_bits=bits,
            estimated_overhead_ms=overhead,
            dscp_value=metrics.dscp_value,
            dscp_label=dscp_name(metrics.dscp_value),
            reason=reason,
        )

    def should_switch(self, current: str, metrics: PolicyMetrics) -> bool:
        return self.evaluate(metrics).algorithm != current

    @staticmethod
    def pick_stronger(a: str, b: str) -> str:
        rank = {"AES-256-GCM": 3, "ChaCha20-Poly1305": 2, "AES-128-GCM": 1}
        return a if rank.get(a, 0) >= rank.get(b, 0) else b


# ── Per-frame selection used by both proxies ──────────────────────────────────

# One engine per process, so per-flow DSCP baselines (used for downgrade
# detection) are shared across all switch connections handled by a proxy.
_FRAME_ENGINE: Optional[PolicyEngine] = None


def select_frame_cipher(frame: bytes) -> str:
    """Cipher for one plaintext OpenFlow frame.

    PACKET_IN/PACKET_OUT inherit the DSCP class of the carried IPv4 packet
    (with per-flow downgrade detection); every other OpenFlow message is
    switch<->controller control traffic and is treated as CS6 (AES-256-GCM),
    subject only to the global override.
    """
    global _FRAME_ENGINE
    from pqc_sdn.policy.ofparse import parse_ipv4_flow
    parsed = parse_ipv4_flow(frame)
    if parsed is None:
        return get_cipher_override() or _POLICY[DscpClass.CS6][1]
    if _FRAME_ENGINE is None:
        _FRAME_ENGINE = PolicyEngine()
    dscp, flow_key = parsed
    cipher, _ = _FRAME_ENGINE.select_cipher(flow_key, dscp)
    return cipher
