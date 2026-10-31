"""Persistent controller-proxy identity and pinned-key loading.

ctrl_proxy loads (or on first start creates) a long-term ML-DSA-87 keypair
from disk, so its public key stays stable across restarts and can be pinned
by switch proxies. The secret key file is created with mode 0600.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pqc_sdn.crypto.signatures import SignatureKeyPair, SignatureScheme
from pqc_sdn.settings import get_settings


def _resolve(path: str) -> Path:
    p = Path(path)
    if not p.is_absolute():
        p = Path(__file__).resolve().parents[3] / p
    return p


def load_or_create_identity(
    pk_path: Optional[str] = None, sk_path: Optional[str] = None
) -> SignatureKeyPair:
    settings = get_settings().proxy
    pk_file = _resolve(pk_path or settings.identity_public_key_file)
    sk_file = _resolve(sk_path or settings.identity_secret_key_file)

    if pk_file.is_file() and sk_file.is_file():
        return SignatureKeyPair(pk_file.read_bytes(), sk_file.read_bytes())

    kp = SignatureScheme().keygen()
    pk_file.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(sk_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(kp.secret_key)
    pk_file.write_bytes(kp.public_key)
    return kp


_PIN_CACHE: dict = {}


def load_pinned_key() -> Optional[bytes]:
    """Return the pinned controller identity key, or None if unconfigured.

    Priority: proxy.pinned_identity_key (hex) > proxy.identity_public_key_file.
    Cached per settings object (it is read on every switch handshake).
    """
    settings = get_settings().proxy
    key = (settings.pinned_identity_key, settings.identity_public_key_file)
    if key not in _PIN_CACHE:
        _PIN_CACHE[key] = _load_pinned_key(settings)
    return _PIN_CACHE[key]


def _load_pinned_key(settings) -> Optional[bytes]:
    if settings.pinned_identity_key:
        return bytes.fromhex(settings.pinned_identity_key)
    pk_file = _resolve(settings.identity_public_key_file)
    if pk_file.is_file():
        return pk_file.read_bytes()
    return None


def load_or_create_switch_identity() -> SignatureKeyPair:
    settings = get_settings().proxy
    return load_or_create_identity(settings.switch_identity_public_key_file,
                                   settings.switch_identity_secret_key_file)


def load_authorized_switch_keys() -> list:
    """Allowlist of switch-proxy public keys (hex, one per line; '#' comments)."""
    path = _resolve(get_settings().proxy.authorized_switch_keys_file)
    if not path.is_file():
        return []
    keys = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            keys.append(bytes.fromhex(line))
    return keys


def authorize_switch_key(public_key: bytes) -> None:
    """Provisioning helper: add a switch-proxy key to the allowlist."""
    path = _resolve(get_settings().proxy.authorized_switch_keys_file)
    existing = load_authorized_switch_keys()
    if any(k == public_key for k in existing):
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(public_key.hex() + "\n")
