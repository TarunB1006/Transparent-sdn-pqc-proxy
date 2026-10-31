"""Handshake message types (compact binary encoding).

Every message is encoded as::

    type (1B) | version (1B) | field_1 | field_2 | ...

with fields encoded as:

    str        u16 length + UTF-8 bytes
    bytes      u32 length + raw bytes
    float      IEEE-754 double (8B, big-endian)
    List[str]  u8 count + count * str

Raw binary encoding keeps KEM public keys, ciphertexts, and ML-DSA keys and
signatures at their FIPS 203/204 sizes on the wire (the previous JSON/hex
encoding doubled them).  Decoding is strict: wrong type tag, unknown version,
truncation, and trailing bytes all raise ValueError.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import List, Tuple

_VERSION = 1

_TYPE_CLIENT_HELLO = 1
_TYPE_SERVER_HELLO = 2
_TYPE_CERTIFICATE = 3
_TYPE_ENCAPSULATED_KEY = 4
_TYPE_CLIENT_AUTH = 5

# Upper bound for any single bytes field (largest real field is an ML-DSA-87
# signature at 4627 B); guards against memory-exhaustion via forged lengths.
_MAX_FIELD = 65536

DEFAULT_CIPHERS = ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]


class _Writer:
    def __init__(self, msg_type: int) -> None:
        self._parts = [struct.pack("!BB", msg_type, _VERSION)]

    def str(self, value: str) -> "_Writer":
        raw = value.encode()
        self._parts.append(struct.pack("!H", len(raw)) + raw)
        return self

    def bytes(self, value: bytes) -> "_Writer":
        self._parts.append(struct.pack("!I", len(value)) + value)
        return self

    def float(self, value: float) -> "_Writer":
        self._parts.append(struct.pack("!d", value))
        return self

    def str_list(self, values: List[str]) -> "_Writer":
        self._parts.append(struct.pack("!B", len(values)))
        for v in values:
            self.str(v)
        return self

    def done(self) -> bytes:
        return b"".join(self._parts)


class _Reader:
    def __init__(self, data: bytes, msg_type: int) -> None:
        self._data = data
        self._pos = 0
        got_type, version = self._unpack("!BB")
        if got_type != msg_type:
            raise ValueError(f"unexpected message type {got_type} (want {msg_type})")
        if version != _VERSION:
            raise ValueError(f"unsupported message version {version}")

    def _take(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise ValueError("truncated handshake message")
        out = self._data[self._pos:self._pos + n]
        self._pos += n
        return out

    def _unpack(self, fmt: str) -> Tuple:
        return struct.unpack(fmt, self._take(struct.calcsize(fmt)))

    def str(self) -> str:
        (n,) = self._unpack("!H")
        return self._take(n).decode()

    def bytes(self) -> bytes:
        (n,) = self._unpack("!I")
        if n > _MAX_FIELD:
            raise ValueError(f"field too large: {n}")
        return self._take(n)

    def float(self) -> float:
        return self._unpack("!d")[0]

    def str_list(self) -> List[str]:
        (n,) = self._unpack("!B")
        return [self.str() for _ in range(n)]

    def done(self) -> None:
        if self._pos != len(self._data):
            raise ValueError("trailing bytes after handshake message")


@dataclass
class ClientHello:
    sender_id: str
    ml_kem_variant: str
    kem_public_key: bytes
    supported_ciphers: List[str] = field(default_factory=lambda: list(DEFAULT_CIPHERS))
    timestamp: float = field(default_factory=time.time)
    nonce: bytes = field(default_factory=lambda: os.urandom(32))
    session_id: str = field(default_factory=lambda: os.urandom(16).hex())

    def serialize(self) -> bytes:
        return (_Writer(_TYPE_CLIENT_HELLO)
                .str(self.sender_id)
                .str(self.ml_kem_variant)
                .bytes(self.kem_public_key)
                .str_list(self.supported_ciphers)
                .float(self.timestamp)
                .bytes(self.nonce)
                .str(self.session_id)
                .done())

    @classmethod
    def deserialize(cls, data: bytes) -> "ClientHello":
        r = _Reader(data, _TYPE_CLIENT_HELLO)
        msg = cls(
            sender_id=r.str(),
            ml_kem_variant=r.str(),
            kem_public_key=r.bytes(),
            supported_ciphers=r.str_list(),
            timestamp=r.float(),
            nonce=r.bytes(),
            session_id=r.str(),
        )
        r.done()
        return msg


@dataclass
class ServerHello:
    sender_id: str
    session_id: str
    ml_kem_variant: str
    selected_cipher: str = "AES-256-GCM"
    timestamp: float = field(default_factory=time.time)

    def serialize(self) -> bytes:
        return (_Writer(_TYPE_SERVER_HELLO)
                .str(self.sender_id)
                .str(self.session_id)
                .str(self.ml_kem_variant)
                .str(self.selected_cipher)
                .float(self.timestamp)
                .done())

    @classmethod
    def deserialize(cls, data: bytes) -> "ServerHello":
        r = _Reader(data, _TYPE_SERVER_HELLO)
        msg = cls(
            sender_id=r.str(),
            session_id=r.str(),
            ml_kem_variant=r.str(),
            selected_cipher=r.str(),
            timestamp=r.float(),
        )
        r.done()
        return msg


@dataclass
class Certificate:
    issuer_id: str
    subject_id: str
    public_key: bytes
    signature: bytes
    timestamp: float = field(default_factory=time.time)

    def serialize(self) -> bytes:
        return (_Writer(_TYPE_CERTIFICATE)
                .str(self.issuer_id)
                .str(self.subject_id)
                .bytes(self.public_key)
                .bytes(self.signature)
                .float(self.timestamp)
                .done())

    @classmethod
    def deserialize(cls, data: bytes) -> "Certificate":
        r = _Reader(data, _TYPE_CERTIFICATE)
        msg = cls(
            issuer_id=r.str(),
            subject_id=r.str(),
            public_key=r.bytes(),
            signature=r.bytes(),
            timestamp=r.float(),
        )
        r.done()
        return msg


@dataclass
class EncapsulatedKey:
    ciphertext: bytes
    sender_id: str
    session_id: str

    def serialize(self) -> bytes:
        return (_Writer(_TYPE_ENCAPSULATED_KEY)
                .bytes(self.ciphertext)
                .str(self.sender_id)
                .str(self.session_id)
                .done())

    @classmethod
    def deserialize(cls, data: bytes) -> "EncapsulatedKey":
        r = _Reader(data, _TYPE_ENCAPSULATED_KEY)
        msg = cls(
            ciphertext=r.bytes(),
            sender_id=r.str(),
            session_id=r.str(),
        )
        r.done()
        return msg


@dataclass
class ClientAuth:
    """Switch-proxy authentication, sent as the first frame inside the tunnel.

    signature = ML-DSA-87(sk_switch, "pqc-sdn-client-auth-v1|" || h || SHA256(m3)),
    where h is the handshake transcript hash and m3 the controller certificate.
    """
    sender_id: str
    public_key: bytes
    signature: bytes

    MAGIC = b"PQCAUTH1"

    def serialize(self) -> bytes:
        return (_Writer(_TYPE_CLIENT_AUTH)
                .str(self.sender_id)
                .bytes(self.public_key)
                .bytes(self.signature)
                .done())

    @classmethod
    def deserialize(cls, data: bytes) -> "ClientAuth":
        r = _Reader(data, _TYPE_CLIENT_AUTH)
        msg = cls(sender_id=r.str(), public_key=r.bytes(), signature=r.bytes())
        r.done()
        return msg
