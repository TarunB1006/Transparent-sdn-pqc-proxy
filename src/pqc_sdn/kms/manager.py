"""In-memory key lifecycle management."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Dict, Optional

from pqc_sdn.crypto.kem import Kem, KemVariant, parse_kem_variant

log = logging.getLogger(__name__)


@dataclass
class KeyRecord:
    key_id: str
    owner_id: str
    variant: str
    public_key: bytes
    secret_key: bytes
    created_at: float
    expires_at: float


class KeyManager:
    """Generate and track ML-KEM keys for devices and switches."""

    DEFAULT_TTL_SECONDS = 48 * 3600

    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._keys: Dict[str, KeyRecord] = {}
        self._counter = 0

    def _next_id(self, owner: str, variant: KemVariant) -> str:
        self._counter += 1
        return f"{variant.value}-{owner}-{self._counter}-{int(time.time())}"

    def generate(self, owner_id: str, variant: KemVariant) -> KeyRecord:
        kem = Kem(variant)
        kp = kem.keygen()
        now = time.time()
        key_id = self._next_id(owner_id, variant)
        record = KeyRecord(
            key_id=key_id,
            owner_id=owner_id,
            variant=variant.value,
            public_key=kp.public_key,
            secret_key=kp.secret_key,
            created_at=now,
            expires_at=now + self._ttl,
        )
        self._keys[key_id] = record
        log.debug("[kms] generated key=%s owner=%s variant=%s ttl=%ds",
                  key_id, owner_id, variant.value, int(self._ttl))
        return record

    def onboarding(self, device_id: str) -> KeyRecord:
        return self.generate(device_id, KemVariant.ML_KEM_512)

    def control_plane(self, switch_id: str) -> KeyRecord:
        return self.generate(switch_id, KemVariant.ML_KEM_1024)

    def refresh(self, owner_id: str) -> KeyRecord:
        return self.generate(owner_id, KemVariant.ML_KEM_768)

    def get(self, key_id: str) -> Optional[KeyRecord]:
        return self._keys.get(key_id)
