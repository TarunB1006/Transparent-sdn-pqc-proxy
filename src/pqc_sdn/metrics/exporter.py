"""Prometheus metrics (Grafana-compatible names)."""

from __future__ import annotations

import logging
import socket
import threading
from wsgiref.simple_server import make_server, WSGIServer

from prometheus_client import Counter, Gauge, Histogram, make_wsgi_app

logger = logging.getLogger(__name__)

HANDSHAKE_SECONDS = Histogram(
    "pqc_handshake_duration_seconds",
    "PQC handshake duration",
    ["dpid", "variant"],
    buckets=(0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)

THROUGHPUT_BPS = Gauge(
    "pqc_throughput_bps",
    "Port throughput bps",
    ["dpid", "port_no", "direction"],
)

LINK_UTILIZATION = Gauge(
    "pqc_link_utilization",
    "Port utilization ratio",
    ["dpid", "port_no"],
)

FLOW_ALGORITHM = Gauge(
    "pqc_flow_algorithm",
    "Active algorithm for flow",
    ["src_ip", "dst_ip", "algorithm", "dscp", "dscp_name", "ingress_dpid"],
)

PACKET_IN_SECONDS = Histogram(
    "pqc_packet_in_processing_seconds",
    "Packet-in to flow-mod latency",
    ["dpid"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0),
)

PQC_OVERHEAD_BYTES = Gauge(
    "pqc_overhead_bps",
    "PQC encapsulation overhead per port in bits/s (nonce + auth tag + padding vs payload)",
    ["dpid", "port_no"],
)

PQC_ACTIVE_SESSIONS = Gauge(
    "pqc_active_sessions",
    "Number of active PQC-secured control-plane sessions",
)

PQC_ENCRYPTED_BYTES = Gauge(
    "pqc_encrypted_bytes_total",
    "Cumulative bytes of OpenFlow traffic protected by PQC session (per switch)",
    ["dpid"],
)

# ── Security / Attack-Detection Metrics ──────────────────────────────────────

# Must be Counter (not Gauge) — monotonically increasing event counts.
# Prometheus rate()/increase() functions require Counter type; Gauge would
# produce silent garbage in Grafana alert rules and dashboards.
PQC_REPLAY_ATTEMPTS = Counter(
    "pqc_replay_attempts_total",
    "Cumulative replay-attack attempts detected (duplicate sequence numbers)",
    ["dpid"],
)

PQC_HANDSHAKE_FAILURES = Counter(
    "pqc_handshake_failures_total",
    "Cumulative failed PQC handshakes (rogue switch / bad certificate)",
    ["dpid", "reason"],
)

PQC_DOWNGRADE_ATTEMPTS = Counter(
    "pqc_downgrade_attempts_total",
    "Cumulative algorithm-downgrade attempts detected via DSCP manipulation",
    ["src_ip", "dst_ip"],
)

PQC_DOS_PACKET_IN_RATE = Gauge(
    "pqc_dos_packet_in_rate",
    "Current PacketIn rate per switch (packets/s) — spike indicates DoS flood",
    ["dpid"],
)

# ── Attack-Simulation / Chaos Metrics ─────────────────────────────────────────
# Used by mgmt_api attack endpoints to record simulated attack state.

PQC_CTRL_PLANE_SATURATION = Gauge(
    "pqc_ctrl_plane_saturation",
    "Simulated control-plane connection count during DoS/exhaustion attacks",
)

PQC_KEY_EXHAUSTION_HANDSHAKES = Counter(
    "pqc_key_exhaustion_handshakes_total",
    "Cumulative forced re-handshakes triggered by key-exhaustion attack simulation",
)

PQC_HARVEST_CAPTURED_BYTES = Gauge(
    "pqc_harvest_captured_bytes",
    "Bytes of ciphertext captured in simulated Harvest-Now-Decrypt-Later scenario",
)

PQC_HARVEST_DECRYPT_SUCCESS = Gauge(
    "pqc_harvest_decrypt_success",
    "Number of ciphertext blocks successfully decrypted in HNDL simulation (always 0 — ML-KEM is robust)",
)

PQC_ECHO_RTT_MS = Gauge(
    "pqc_echo_rtt_ms",
    "Round-trip time of OpenFlow Echo-Request/Reply per switch (ms)",
    ["dpid"],
)

# ── Controller Resource Metrics ───────────────────────────────────────────────
# Exposed here so bench_resources.py can scrape them from /metrics.

PQC_CONTROLLER_CPU_PERCENT = Gauge(
    "pqc_controller_cpu_percent",
    "Controller process CPU utilization (percent, 0–100)",
)

PQC_CONTROLLER_MEMORY_BYTES = Gauge(
    "pqc_controller_memory_bytes",
    "Controller process RSS memory usage (bytes)",
)

# ── Adaptive Engine Metrics ────────────────────────────────────────────────────

PQC_QUEUE_DEPTH = Gauge(
    "pqc_handshake_queue_depth",
    "Number of in-flight ML-KEM handshakes queued in the executor",
)

PQC_ADAPTIVE_KEM_VARIANT = Gauge(
    "pqc_adaptive_cipher_override",
    "Adaptive cipher override state (0=DSCP auto, 1=ChaCha20-Poly1305 forced under load)",
)


class MetricsExporter:
    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port
        self._thread: threading.Thread | None = None
        self._httpd = None

    def start(self) -> int:
        app = make_wsgi_app()
        # SO_REUSEADDR prevents "Address already in use" on restart
        class _ReuseServer(WSGIServer):
            allow_reuse_address = True
        self._httpd = make_server(self._host, self._port, app, server_class=_ReuseServer)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        logger.info("metrics listening on %s:%d/metrics", self._host, self._port)
        return self._port

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
