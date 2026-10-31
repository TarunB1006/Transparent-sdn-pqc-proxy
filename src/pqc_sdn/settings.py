"""Environment-aware configuration loading."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from pqc_sdn.exceptions import ConfigurationError


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_or_generate_api_token() -> str:
    """Load API token from file, or generate and persist a new one.

    The token is stored in config/.api_token (gitignored). This ensures:
    - Fresh installs get a unique random token (not a hardcoded default)
    - All processes on the same machine share the same token
    - The token is never committed to source control
    """
    token_path = _project_root() / "config" / ".api_token"
    # Check environment override first
    env_token = os.environ.get("PQC_API_TOKEN")
    if env_token:
        return env_token
    try:
        if token_path.is_file():
            token = token_path.read_text().strip()
            if len(token) >= 16:
                return token
        # Generate new token
        token = secrets.token_urlsafe(32)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(token + "\n")
        return token
    except (OSError, PermissionError):
        # Fallback: generate a per-process token (won't persist but is still random)
        return secrets.token_urlsafe(32)


_DEFAULT_API_TOKEN = _load_or_generate_api_token()


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    format: str = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


@dataclass(frozen=True)
class CryptoConfig:
    require_liboqs: bool = False
    control_plane_kem: str = "ML-KEM-1024"
    # Lowest KEM tier ctrl_proxy accepts; empty means control_plane_kem.
    min_control_plane_kem: str = ""
    onboarding_kem: str = "ML-KEM-512"
    key_refresh_kem: str = "ML-KEM-768"
    bulk_cipher: str = "AES-256-GCM"
    padding_block_size: int = 256


@dataclass(frozen=True)
class SessionConfig:
    max_timestamp_skew_seconds: float = 30.0
    key_refresh_interval_seconds: int = 86400
    key_refresh_volume_bytes: int = 100 * 1024**3
    ratchet_interval_messages: int = 1000


@dataclass(frozen=True)
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    base_data_port: int = 6634
    controller_host: str = "127.0.0.1"
    controller_port: int = 6652       # switch proxies → ctrl_proxy
    ctrl_proxy_port: int = 6652       # ctrl_proxy listen port
    ctrl_listen_host: str = "127.0.0.1"  # ctrl_proxy listen address
    ryu_port: int = 6653              # ctrl_proxy → Ryu
    controller_api_port: int = 8080
    plan_poll_interval_seconds: float = 0.5
    read_buffer_size: int = 65536
    api_token: str = field(default_factory=lambda: _DEFAULT_API_TOKEN)
    tls_cert: str = "certs/controller.crt"
    tls_key: str = "certs/controller.key"
    pinned_identity_key: str = ""     # hex-encoded ctrl_proxy identity public key for certificate pinning
    # Pinned key file used when pinned_identity_key is empty. ctrl_proxy writes
    # its persistent ML-DSA-87 public key here; it is distributed to switch
    # proxies out of band (in the single-host testbed both read the same file).
    identity_public_key_file: str = "certs/ctrl_identity.pk"
    identity_secret_key_file: str = "certs/ctrl_identity.sk"
    # Switch-proxy identity and the controller-side allowlist of authorized
    # switch-proxy keys (one hex key per line) for mutual authentication.
    switch_identity_public_key_file: str = "certs/sw_identity.pk"
    switch_identity_secret_key_file: str = "certs/sw_identity.sk"
    authorized_switch_keys_file: str = "certs/authorized_switches.txt"
    mutual_auth: bool = True
    # Fail closed: switch proxies refuse handshakes without a pinned identity.
    # Can be disabled only for experiments that model an unpinned deployment.
    require_pinning: bool = True
    # Legacy plan-poll mode (PQC\x00) is disabled unless explicitly enabled.
    allow_legacy_plan_mode: bool = False
    # Report session metadata to plan_api for the management dashboard. Off by
    # default: it costs an HTTPS request per switch connection and encryption
    # does not depend on it.
    register_sessions: bool = False


@dataclass(frozen=True)
class MetricsConfig:
    host: str = "0.0.0.0"
    port: int = 9101


@dataclass(frozen=True)
class RoutingConfig:
    link_capacity_bps: int = 10_000_000
    utilization_weight: float = 0.7
    crypto_overhead_weight: float = 0.3


@dataclass(frozen=True)
class ControllerConfig:
    key_refresh_poll_seconds: int = 30
    key_refresh_ttl_seconds: int = 60
    port_stats_interval_seconds: int = 5
    api_token: str = field(default_factory=lambda: _DEFAULT_API_TOKEN)
    # Legacy plan-poll mode: run a simulated in-process handshake per switch.
    inprocess_handshake: bool = False


@dataclass(frozen=True)
class AdaptiveConfig:
    enabled: bool = False
    cpu_high_pct: float = 85.0
    cpu_low_pct: float = 40.0
    latency_high_ms: float = 5.0
    latency_low_ms: float = 1.0
    queue_depth_high: int = 20
    queue_depth_low: int = 5
    hold_seconds: float = 10.0
    poll_interval_seconds: float = 2.0


@dataclass(frozen=True)
class Settings:
    environment: str = "development"
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    session: SessionConfig = field(default_factory=SessionConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    controller: ControllerConfig = field(default_factory=ControllerConfig)
    adaptive: AdaptiveConfig = field(default_factory=AdaptiveConfig)


def _merge_dataclass(cls, data: dict[str, Any]):
    if not data:
        return cls()
    allowed = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    filtered = {k: v for k, v in data.items() if k in allowed}
    return cls(**filtered)


def load_settings(config_path: Optional[Path] = None) -> Settings:
    """Load settings from YAML with optional override path and env PQC_SDN_CONFIG."""
    path = config_path
    if path is None:
        env_path = os.environ.get("PQC_SDN_CONFIG")
        path = Path(env_path) if env_path else _project_root() / "config" / "default.yaml"

    if not path.is_file():
        raise ConfigurationError(f"Configuration file not found: {path}")

    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    return Settings(
        environment=str(raw.get("environment", "development")),
        logging=_merge_dataclass(LoggingConfig, raw.get("logging", {})),
        crypto=_merge_dataclass(CryptoConfig, raw.get("crypto", {})),
        session=_merge_dataclass(SessionConfig, raw.get("session", {})),
        proxy=_merge_dataclass(ProxyConfig, raw.get("proxy", {})),
        metrics=_merge_dataclass(MetricsConfig, raw.get("metrics", {})),
        routing=_merge_dataclass(RoutingConfig, raw.get("routing", {})),
        controller=_merge_dataclass(ControllerConfig, raw.get("controller", {})),
        adaptive=_merge_dataclass(AdaptiveConfig, raw.get("adaptive", {})),
    )


# Module-level singleton (lazy)
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
        import logging
        _log = logging.getLogger(__name__)
        _log.debug("[settings] loaded: env=%s kem=%s cipher=%s adaptive=%s",
                   _settings.environment, _settings.crypto.control_plane_kem,
                   _settings.crypto.bulk_cipher, _settings.adaptive.enabled)
    return _settings


def reset_settings() -> None:
    """Reset cached settings (for tests)."""
    global _settings
    _settings = None
