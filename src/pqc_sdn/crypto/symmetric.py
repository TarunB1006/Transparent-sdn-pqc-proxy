"""AES-256-GCM authenticated encryption."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from pqc_sdn.exceptions import CryptoError

NONCE_SIZE = 12


@dataclass(frozen=True)
class AeadCiphertext:
    nonce: bytes
    ciphertext: bytes


class AeadCipher:
    """AEAD Cipher supporting AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305."""

    def __init__(self, key: bytes, padding_block_size: int = 256, algorithm: str = "AES-256-GCM") -> None:
        self.algorithm = algorithm
        self._padding_block = padding_block_size
        
        if algorithm == "AES-128-GCM":
            if len(key) != 16:
                raise CryptoError("AES-128-GCM key must be 16 bytes")
            self._aead = AESGCM(key)
        elif algorithm == "AES-256-GCM":
            if len(key) != 32:
                raise CryptoError("AES-256-GCM key must be 32 bytes")
            self._aead = AESGCM(key)
        elif algorithm == "ChaCha20-Poly1305":
            if len(key) != 32:
                raise CryptoError("ChaCha20-Poly1305 key must be 32 bytes")
            self._aead = ChaCha20Poly1305(key)
        else:
            raise CryptoError(f"Unsupported algorithm: {algorithm}")

    @staticmethod
    def generate_key(algorithm: str = "AES-256-GCM") -> bytes:
        if algorithm == "AES-128-GCM":
            return AESGCM.generate_key(bit_length=128)
        elif algorithm == "ChaCha20-Poly1305":
            return ChaCha20Poly1305.generate_key()
        else:
            return AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> AeadCiphertext:
        payload = self._pad(plaintext) if self._padding_block > 0 else plaintext
        nonce = os.urandom(NONCE_SIZE)
        return AeadCiphertext(nonce=nonce, ciphertext=self._aead.encrypt(nonce, payload, aad))

    def decrypt(
        self, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None
    ) -> bytes:
        try:
            plain = self._aead.decrypt(nonce, ciphertext, aad)
        except Exception:
            # Constant-time mitigation: perform dummy operations equivalent to
            # the success path (unpad + memory copy) so the error path timing
            # is closer to the success path. This reduces (but cannot eliminate)
            # the timing delta inherent in AEAD implementations where valid
            # decryption processes more data than tag rejection.
            if self._padding_block > 0 and len(ciphertext) >= 4:
                dummy = bytes(ciphertext[:min(len(ciphertext), self._padding_block)])
                _ = self._unpad(dummy)
            raise
        return self._unpad(plain) if self._padding_block > 0 else plain

    def _pad(self, data: bytes) -> bytes:
        header = struct.pack(">I", len(data))
        padded = header + data
        remainder = len(padded) % self._padding_block
        if remainder:
            padded += os.urandom(self._padding_block - remainder)
        return padded

    def _unpad(self, data: bytes) -> bytes:
        if len(data) < 4:
            return data
        length = struct.unpack(">I", data[:4])[0]
        return data[4 : 4 + length]
