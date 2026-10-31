"""Wire framing for encrypted OpenFlow transport.

Wire format v2 (with cipher_id for DSCP-adaptive cipher selection):
  [total_len: 4B] [seq: 4B] [epoch: 1B] [cipher_id: 1B] [nonce: 12B] [ciphertext: ...]

cipher_id values:
  0 = AES-256-GCM     (high-security: CS6, CS7, AF1x)
  1 = AES-128-GCM     (balanced: BE, AF2x, AF3x, CS5)
  2 = ChaCha20-Poly1305 (latency-sensitive: EF, CS4, AF4x)

Backward compat: if cipher_id is not in {0,1,2}, treat as AES-256-GCM (v1 format).
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from pqc_sdn.tls.session import SecurePacket

# v2 header: total_len(4) + seq(4) + epoch(1) + cipher_id(1) + nonce(12) = 22 bytes
HEADER = struct.Struct("!IIBB")   # total_len, seq, epoch, cipher_id
NONCE_SIZE = 12

# Cipher ID constants
CIPHER_AES_256_GCM       = 0
CIPHER_AES_128_GCM       = 1
CIPHER_CHACHA20_POLY1305 = 2

CIPHER_NAME_TO_ID = {
    "AES-256-GCM":       CIPHER_AES_256_GCM,
    "AES-128-GCM":       CIPHER_AES_128_GCM,
    "ChaCha20-Poly1305": CIPHER_CHACHA20_POLY1305,
}

CIPHER_ID_TO_NAME = {v: k for k, v in CIPHER_NAME_TO_ID.items()}


@dataclass(frozen=True)
class WireFrame:
    sequence_number: int
    epoch: int
    cipher_id: int
    nonce: bytes
    ciphertext: bytes

    @property
    def cipher_name(self) -> str:
        return CIPHER_ID_TO_NAME.get(self.cipher_id, "AES-256-GCM")


def encode_frame(packet: SecurePacket, cipher_id: int = CIPHER_AES_256_GCM) -> bytes:
    """Encode a SecurePacket into wire bytes with cipher_id tag."""
    total = HEADER.size + NONCE_SIZE + len(packet.ciphertext)
    header = HEADER.pack(total, packet.sequence_number, packet.epoch, cipher_id)
    return header + packet.nonce + packet.ciphertext


def decode_frame(data: bytes) -> WireFrame:
    """Decode wire bytes into a WireFrame."""
    if len(data) < HEADER.size + NONCE_SIZE:
        raise ValueError("frame too short")
    total_len, seq, epoch, cipher_id = HEADER.unpack_from(data)
    nonce = data[HEADER.size : HEADER.size + NONCE_SIZE]
    ciphertext = data[HEADER.size + NONCE_SIZE : total_len]
    return WireFrame(seq, epoch, cipher_id, nonce, ciphertext)


def packet_from_frame(frame: WireFrame, key_id: str) -> SecurePacket:
    """Convert a WireFrame back to a SecurePacket for decryption."""
    return SecurePacket(
        ciphertext=frame.ciphertext,
        nonce=frame.nonce,
        sequence_number=frame.sequence_number,
        timestamp=time.time(),
        key_id=key_id,
        epoch=frame.epoch,
    )
