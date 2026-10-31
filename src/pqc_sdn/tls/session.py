"""AEAD secure session with replay protection."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqc_sdn.crypto.symmetric import AeadCipher
from pqc_sdn.exceptions import SessionError
from pqc_sdn.settings import get_settings

log = logging.getLogger(__name__)


@dataclass
class SecurePacket:
    ciphertext: bytes
    nonce: bytes
    sequence_number: int
    timestamp: float
    key_id: str
    epoch: int = 0


def derive_directional_keys(
    shared_secret: bytes, session_id: str
) -> tuple[bytes, bytes]:
    """HKDF split for independent send/receive AEAD keys."""
    base = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"pqc-sdn-session-{session_id}".encode(),
    ).derive(shared_secret)
    send_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base,
        info=b"send",
    ).derive(shared_secret)
    recv_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base,
        info=b"recv",
    ).derive(shared_secret)
    return send_key, recv_key


def _check_sequence(seq: int, expected_min: int, remote_id: str) -> None:
    """Reject any frame whose sequence number is not strictly greater than the
    last accepted one.

    The tunnel runs over TCP, so legitimate frames always arrive in order;
    any seq <= the last accepted value is a replay (or reordering by an
    attacker) and is rejected. Unlike a bounded "seen" set, this has no
    window to fall out of, so arbitrarily old frames are rejected too.
    """
    if seq < expected_min:
        try:
            from pqc_sdn.metrics.exporter import PQC_REPLAY_ATTEMPTS
            PQC_REPLAY_ATTEMPTS.labels(dpid=remote_id).inc()
        except Exception:
            pass
        raise SessionError(f"replay detected seq={seq} (expected >= {expected_min})")


class SecureSession:
    """Bidirectional AES-256-GCM session with sequence and timestamp checks."""

    def __init__(
        self,
        session_id: str,
        send_key: bytes,
        recv_key: bytes,
        key_id: str,
        local_id: str,
        remote_id: str,
        algorithm: str = "AES-256-GCM",
    ) -> None:
        settings = get_settings()
        pad = settings.crypto.padding_block_size
        self.session_id = session_id
        self.key_id = key_id
        self.local_id = local_id
        self.remote_id = remote_id
        self.algorithm = algorithm
        self._send_key_bytes = send_key
        self._recv_key_bytes = recv_key
        self._send_cipher = AeadCipher(send_key, pad, algorithm=algorithm)
        self._recv_cipher = AeadCipher(recv_key, pad, algorithm=algorithm)
        self._send_seq = 0
        self._recv_seq = 0
        self._skew = settings.session.max_timestamp_skew_seconds
        self._created_at = time.time()
        self._bytes_sent = 0
        self._bytes_received = 0
        self._active = True
        self._epoch = 0
        self._ratchet_interval = settings.session.ratchet_interval_messages
        log.debug("[session] created id=%s algo=%s local=%s remote=%s",
                  session_id, algorithm, local_id, remote_id)

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def send_key(self) -> bytes:
        return self._send_key_bytes

    @property
    def recv_key(self) -> bytes:
        return self._recv_key_bytes

    # Maximum sequence number before the 32-bit wire format overflows.
    # Reserve 1024 to allow in-flight messages to complete before shutdown.
    _MAX_SEQ = (2**32) - 1024

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> SecurePacket:
        if not self._active:
            raise SessionError("session is closed")
        if self._send_seq >= self._MAX_SEQ:
            self._active = False
            raise SessionError(
                f"session exhausted: sequence number reached {self._send_seq} "
                f"(max {self._MAX_SEQ}) — session must be renegotiated"
            )
        # Build AAD: bind sequence number + epoch into the GCM auth tag
        # so any wire-level modification of these fields is detected.
        seq_bytes = self._send_seq.to_bytes(4, "big")
        epoch_bytes = self._epoch.to_bytes(1, "big")
        frame_aad = seq_bytes + epoch_bytes + (aad or b"")
        result = self._send_cipher.encrypt(plaintext, frame_aad)
        packet = SecurePacket(
            ciphertext=result.ciphertext,
            nonce=result.nonce,
            sequence_number=self._send_seq,
            timestamp=time.time(),
            key_id=self.key_id,
            epoch=self._epoch,
        )
        self._send_seq += 1
        self._bytes_sent += len(plaintext)
        # Ratchet disabled: one-sided key rotation breaks decryption at the peer
        # without an out-of-band key sync mechanism.
        return packet

    def decrypt(self, packet: SecurePacket) -> bytes:
        if not self._active:
            raise SessionError("session is closed")
        _check_sequence(packet.sequence_number, self._recv_seq, self.remote_id)

        # Reconstruct AAD from the packet's sequence/epoch — must match what
        # the sender used, or the GCM auth tag verification will fail.
        seq_bytes = packet.sequence_number.to_bytes(4, "big")
        epoch_bytes = packet.epoch.to_bytes(1, "big")
        frame_aad = seq_bytes + epoch_bytes

        plain = self._recv_cipher.decrypt(packet.nonce, packet.ciphertext, frame_aad)
        # Advance only after the AEAD tag verified, so a forged frame cannot
        # move the window forward.
        self._recv_seq = packet.sequence_number + 1
        self._bytes_received += len(plain)
        return plain

    # Key ratcheting is disabled: one-sided rotation breaks decryption at the
    # peer without an out-of-band key sync mechanism. The _ratchet_send_key
    # method has been removed to avoid dead code that references nonexistent
    # AeadCipher internals. If ratcheting is needed in the future, implement
    # a coordinated ratchet protocol between both session endpoints.

    def close(self) -> None:
        self._active = False
        log.debug("[session] closed id=%s sent=%d recv=%d",
                  self.session_id, self._bytes_sent, self._bytes_received)


# ── Multi-Cipher Session for DSCP-Adaptive Proxy ──────────────────────────────

class MultiCipherSession:
    """Session that supports per-frame cipher selection via DSCP policy.

    Maintains three AEAD cipher instances (AES-256-GCM, AES-128-GCM,
    ChaCha20-Poly1305) with the same underlying key material. The caller
    selects which cipher to use per frame via cipher_id.

    This enables the DSCP-adaptive architecture:
      - Control traffic (CS6/CS7): cipher_id=0 → AES-256-GCM
      - Bulk traffic (BE/AF2x):   cipher_id=1 → AES-128-GCM
      - VoIP/real-time (EF/CS4):  cipher_id=2 → ChaCha20-Poly1305

    Key derivation: each cipher derives its own key from the base key
    via HKDF-SHA256 with a distinct info label per algorithm. This avoids
    cross-algorithm key reuse and ensures key independence.
    """

    ALGORITHMS = ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]

    @staticmethod
    def _derive_cipher_key(base_key: bytes, algo: str, direction: str) -> bytes:
        """Derive a per-cipher key using HKDF-SHA256.
        
        The base_key is already directional (send_key or recv_key from the
        handshake), so the direction parameter is not included in the info
        label. Only the algorithm name differentiates per-cipher keys.
        """
        key_len = 16 if algo == "AES-128-GCM" else 32
        return HKDF(
            algorithm=hashes.SHA256(),
            length=key_len,
            salt=None,
            info=f"pqc-sdn-cipher|{algo}".encode(),
        ).derive(base_key)

    def __init__(
        self,
        session_id: str,
        send_key: bytes,    # 32 bytes from KEM handshake
        recv_key: bytes,    # 32 bytes
        key_id: str,
        local_id: str,
        remote_id: str,
    ) -> None:
        settings = get_settings()
        pad = settings.crypto.padding_block_size
        self.session_id = session_id
        self.key_id     = key_id
        self.local_id   = local_id
        self.remote_id  = remote_id
        self._send_key_bytes = send_key
        self._recv_key_bytes = recv_key

        # Derive independent keys per cipher per direction via HKDF
        self._send_ciphers = {}
        self._recv_ciphers = {}
        for algo in self.ALGORITHMS:
            sk = self._derive_cipher_key(send_key, algo, "send")
            rk = self._derive_cipher_key(recv_key, algo, "recv")
            self._send_ciphers[algo] = AeadCipher(sk, pad, algorithm=algo)
            self._recv_ciphers[algo] = AeadCipher(rk, pad, algorithm=algo)

        self._send_seq    = 0
        self._recv_seq    = 0
        self._skew        = settings.session.max_timestamp_skew_seconds
        self._created_at  = time.time()
        self._bytes_sent  = 0
        self._bytes_recv  = 0
        self._active      = True
        self._epoch       = 0

        # Per-cipher stats
        self._cipher_frame_counts = {a: 0 for a in self.ALGORITHMS}

        log.debug("[multi-session] created id=%s local=%s remote=%s",
                  session_id, local_id, remote_id)

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def send_key(self) -> bytes:
        return self._send_key_bytes

    @property
    def recv_key(self) -> bytes:
        return self._recv_key_bytes

    @property
    def cipher_stats(self) -> dict:
        return dict(self._cipher_frame_counts)

    _MAX_SEQ = (2**32) - 1024

    def encrypt(self, plaintext: bytes, cipher_name: str = "AES-256-GCM",
                aad: Optional[bytes] = None) -> SecurePacket:
        """Encrypt with the specified cipher algorithm."""
        if not self._active:
            raise SessionError("session is closed")
        if self._send_seq >= self._MAX_SEQ:
            self._active = False
            raise SessionError("session exhausted")

        cipher = self._send_ciphers.get(cipher_name)
        if cipher is None:
            raise SessionError(f"unknown cipher: {cipher_name}")

        seq_bytes   = self._send_seq.to_bytes(4, "big")
        epoch_bytes = self._epoch.to_bytes(1, "big")
        frame_aad   = seq_bytes + epoch_bytes + (aad or b"")

        result = cipher.encrypt(plaintext, frame_aad)
        packet = SecurePacket(
            ciphertext=result.ciphertext,
            nonce=result.nonce,
            sequence_number=self._send_seq,
            timestamp=time.time(),
            key_id=self.key_id,
            epoch=self._epoch,
        )
        self._send_seq += 1
        self._bytes_sent += len(plaintext)
        self._cipher_frame_counts[cipher_name] += 1
        return packet

    def decrypt(self, packet: SecurePacket,
                cipher_name: str = "AES-256-GCM") -> bytes:
        """Decrypt with the specified cipher algorithm."""
        if not self._active:
            raise SessionError("session is closed")
        _check_sequence(packet.sequence_number, self._recv_seq, self.remote_id)

        cipher = self._recv_ciphers.get(cipher_name)
        if cipher is None:
            raise SessionError(f"unknown cipher: {cipher_name}")

        seq_bytes   = packet.sequence_number.to_bytes(4, "big")
        epoch_bytes = packet.epoch.to_bytes(1, "big")
        frame_aad   = seq_bytes + epoch_bytes

        plain = cipher.decrypt(packet.nonce, packet.ciphertext, frame_aad)
        # Advance only after the AEAD tag verified, so a forged frame cannot
        # move the window forward.
        self._recv_seq = packet.sequence_number + 1
        self._bytes_recv += len(plain)
        return plain

    def close(self) -> None:
        self._active = False
        log.debug("[multi-session] closed id=%s sent=%d recv=%d cipher_stats=%s",
                  self.session_id, self._bytes_sent, self._bytes_recv,
                  self._cipher_frame_counts)
