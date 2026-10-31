"""AdaptiveCipherSelector — hysteresis-guarded symmetric cipher selector.

Under high CPU/latency/queue load, forces ChaCha20-Poly1305 across all flows
(fast software-only cipher, no AES-NI dependency).  When load clears, reverts
to DSCP-driven per-flow cipher selection.

KEM is NEVER touched here.  ML-KEM runs once at handshake time and is fixed
at the deployment-time variant (settings.crypto.control_plane_kem).  Only
the per-frame symmetric cipher adapts to load.

Decision logic:
  HIGH LOAD (any condition true):
    cpu  > cpu_high_pct  (default 85%)
    OR latency > latency_high_ms (default 5 ms)
    OR queue   > queue_depth_high (default 20)
  → cipher override = "ChaCha20-Poly1305"

  LOAD CLEAR (all conditions true):
    cpu  < cpu_low_pct   (default 40%)
    AND latency < latency_low_ms  (default 1 ms)
    AND queue   < queue_depth_low (default 5)
  → cipher override = None  (DSCP auto per-flow)

  HOLD otherwise (or within hold_seconds of the last transition).
"""

from __future__ import annotations

import logging
import time
from typing import Optional, Tuple

from pqc_sdn.adaptive.monitor import LoadMonitor

log = logging.getLogger(__name__)

_HIGH_LOAD_CIPHER = "ChaCha20-Poly1305"


class AdaptiveSelector:
    def __init__(
        self,
        monitor: LoadMonitor,
        *,
        cpu_high_pct: float = 85.0,
        cpu_low_pct: float = 40.0,
        latency_high_ms: float = 5.0,
        latency_low_ms: float = 1.0,
        queue_depth_high: int = 20,
        queue_depth_low: int = 5,
        hold_seconds: float = 10.0,
    ) -> None:
        self._monitor = monitor
        self._cpu_high = cpu_high_pct
        self._cpu_low = cpu_low_pct
        self._lat_high = latency_high_ms
        self._lat_low = latency_low_ms
        self._q_high = queue_depth_high
        self._q_low = queue_depth_low
        self._hold = hold_seconds

        self._high_load: bool = False       # False = DSCP auto, True = ChaCha20 override
        self._last_change: float = 0.0      # monotonic time of last transition
        self._reason: str = "initial"

    # ── public API ─────────────────────────────────────────────────────────────

    @property
    def current_cipher(self) -> Optional[str]:
        """Active cipher override: 'ChaCha20-Poly1305' under load, None = DSCP auto."""
        return _HIGH_LOAD_CIPHER if self._high_load else None

    @property
    def last_reason(self) -> str:
        return self._reason

    def check(self) -> Tuple[Optional[str], bool]:
        """Sample the monitor and apply the load decision.

        Returns (cipher_override, changed) where:
          cipher_override: "ChaCha20-Poly1305" under high load, None when clear.
          changed: True means a transition just occurred and the controller
                   should call set_cipher_override(cipher_override).
        """
        snap = self._monitor.snapshot()
        cpu   = snap["cpu_percent"]
        lat   = snap["latency_ms"]
        queue = snap["queue_depth"]

        now = time.monotonic()
        in_hold = (now - self._last_change) < self._hold

        under_pressure = (
            cpu > self._cpu_high
            or lat > self._lat_high
            or queue > self._q_high
        )

        load_clear = (
            cpu < self._cpu_low
            and lat < self._lat_low
            and queue < self._q_low
        )

        # ── enter high-load mode ───────────────────────────────────────────────
        if under_pressure and not self._high_load and not in_hold:
            self._high_load = True
            self._last_change = now
            self._reason = f"high-load: cpu={cpu:.1f}% lat={lat:.2f}ms q={queue}"
            log.info("[adaptive] cipher → ChaCha20-Poly1305 (%s)", self._reason)
            self._emit_metric()
            return _HIGH_LOAD_CIPHER, True

        # ── return to DSCP auto ────────────────────────────────────────────────
        if load_clear and self._high_load and not in_hold:
            self._high_load = False
            self._last_change = now
            self._reason = f"load-clear: cpu={cpu:.1f}% lat={lat:.2f}ms q={queue}"
            log.info("[adaptive] cipher → auto/DSCP (%s)", self._reason)
            self._emit_metric()
            return None, True

        return self.current_cipher, False

    def state(self) -> dict:
        snap = self._monitor.snapshot()
        return {
            "cipher":       self.current_cipher,
            "high_load":    self._high_load,
            "reason":       self._reason,
            "cpu_pct":      snap["cpu_percent"],
            "latency_ms":   snap["latency_ms"],
            "queue_depth":  snap["queue_depth"],
            "in_hold":      (time.monotonic() - self._last_change) < self._hold,
        }

    # ── internals ──────────────────────────────────────────────────────────────

    def _emit_metric(self) -> None:
        try:
            from pqc_sdn.metrics.exporter import PQC_ADAPTIVE_KEM_VARIANT
            # 0 = DSCP auto, 1 = ChaCha20-Poly1305 override
            PQC_ADAPTIVE_KEM_VARIANT.set(1 if self._high_load else 0)
        except Exception:
            pass
