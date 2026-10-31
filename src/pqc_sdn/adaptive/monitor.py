"""LoadMonitor — background thread that samples controller resource usage.

Tracks three signals fed into the AdaptiveSelector:
  - cpu_percent      : process CPU utilisation (0–100)
  - latency_ms       : exponential moving average of recent handshake latency
  - queue_depth      : number of in-flight handshakes (start/end notifications)

The monitor also updates the Prometheus metrics
  pqc_controller_cpu_percent, pqc_controller_memory_bytes, pqc_queue_depth
so Grafana reflects the live state.
"""

from __future__ import annotations

import logging
import os
import threading
import time

log = logging.getLogger(__name__)

_EMA_ALPHA = 0.2   # weight for newest latency sample in the moving average


class LoadMonitor:
    def __init__(self, poll_interval_seconds: float = 2.0) -> None:
        self._poll = poll_interval_seconds
        self._cpu_pct: float = 0.0
        self._latency_ms: float = 0.0
        self._queue_depth: int = 0
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="pqc-adaptive-monitor"
        )
        self._thread.start()
        log.info("[adaptive] LoadMonitor started (poll=%.1fs)", self._poll)

    def stop(self) -> None:
        self._running = False

    # ── handshake lifecycle hooks (call from controller thread) ───────────────

    def notify_handshake_start(self) -> None:
        with self._lock:
            self._queue_depth += 1

    def notify_handshake_end(self, latency_ms: float) -> None:
        with self._lock:
            self._queue_depth = max(0, self._queue_depth - 1)
            if self._latency_ms == 0.0:
                self._latency_ms = latency_ms
            else:
                self._latency_ms = (
                    _EMA_ALPHA * latency_ms + (1 - _EMA_ALPHA) * self._latency_ms
                )

    # ── read-only properties ──────────────────────────────────────────────────

    @property
    def cpu_percent(self) -> float:
        with self._lock:
            return self._cpu_pct

    @property
    def latency_ms(self) -> float:
        with self._lock:
            return self._latency_ms

    @property
    def queue_depth(self) -> int:
        with self._lock:
            return self._queue_depth

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "cpu_percent":  self._cpu_pct,
                "latency_ms":   self._latency_ms,
                "queue_depth":  self._queue_depth,
            }

    # ── background loop ───────────────────────────────────────────────────────

    def _loop(self) -> None:
        try:
            import psutil
            proc = psutil.Process(os.getpid())
        except ImportError:
            log.warning("[adaptive] psutil not available — CPU monitoring disabled")
            proc = None

        while self._running:
            try:
                if proc is not None:
                    cpu = proc.cpu_percent(interval=self._poll)
                    mem = proc.memory_info().rss
                    with self._lock:
                        self._cpu_pct = cpu
                    self._update_metrics(cpu, mem)
                else:
                    time.sleep(self._poll)
            except Exception as exc:
                log.debug("[adaptive] monitor error: %s", exc)
                time.sleep(self._poll)

    def _update_metrics(self, cpu: float, mem: int) -> None:
        try:
            from pqc_sdn.metrics.exporter import (
                PQC_CONTROLLER_CPU_PERCENT,
                PQC_CONTROLLER_MEMORY_BYTES,
                PQC_QUEUE_DEPTH,
            )
            PQC_CONTROLLER_CPU_PERCENT.set(cpu)
            PQC_CONTROLLER_MEMORY_BYTES.set(mem)
            PQC_QUEUE_DEPTH.set(self._queue_depth)
        except Exception:
            pass
