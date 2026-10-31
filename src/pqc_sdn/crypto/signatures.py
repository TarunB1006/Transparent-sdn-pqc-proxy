"""ML-DSA-87 (FIPS 204) digital signatures."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

try:
    import oqs

    _LIBOQS = True
except ImportError:
    _LIBOQS = False
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

# Backend selection mirrors pqc_sdn.crypto.kem (default "liboqs"): "openssl" uses the
# FIPS 204 implementation in OpenSSL via pyca/cryptography; "liboqs" forces
# liboqs. Public keys and signatures are identical FIPS 204 encodings; secret
# keys differ (OpenSSL: 32-byte seed, liboqs: expanded key) and are dispatched
# by length.
import os
from functools import lru_cache

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
    _OPENSSL_SIG = True
except ImportError:
    _OPENSSL_SIG = False

_SEED_LEN = 32


@lru_cache(maxsize=8)
def _openssl_signer(seed: bytes):
    return _mldsa.MLDSA87PrivateKey.from_seed_bytes(seed)


@lru_cache(maxsize=64)
def _openssl_verifier(public_key: bytes):
    return _mldsa.MLDSA87PublicKey.from_public_bytes(public_key)


def _use_openssl() -> bool:
    return _OPENSSL_SIG and os.environ.get("PQC_PQ_BACKEND", "liboqs") == "openssl"

_OQS_SIG = "ML-DSA-87"
_PK_SIZE = 2592
_SK_SIZE = 4896
_SIG_SIZE = 4595


@dataclass(frozen=True)
class SignatureKeyPair:
    public_key: bytes
    secret_key: bytes


class SignatureScheme:
    """ML-DSA-87 with liboqs or Ed25519 fallback."""

    def keygen(self) -> SignatureKeyPair:
        if _use_openssl():
            priv = _mldsa.MLDSA87PrivateKey.generate()
            return SignatureKeyPair(priv.public_key().public_bytes_raw(),
                                    priv.private_bytes_raw())
        if _LIBOQS:
            with oqs.Signature(_OQS_SIG) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()
            return SignatureKeyPair(public_key, secret_key)

        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        return SignatureKeyPair(
            public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if _OPENSSL_SIG and len(secret_key) == _SEED_LEN:
            return _openssl_signer(bytes(secret_key)).sign(message)
        if _LIBOQS:
            with oqs.Signature(_OQS_SIG, secret_key=secret_key) as sig:
                return sig.sign(message)

        key = Ed25519PrivateKey.from_private_bytes(secret_key[:32])
        return key.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if _use_openssl() and len(public_key) == _PK_SIZE:
            try:
                _openssl_verifier(bytes(public_key)).verify(signature, message)
                return True
            except (InvalidSignature, ValueError):
                return False
        if _LIBOQS:
            with oqs.Signature(_OQS_SIG) as sig:
                return sig.verify(message, signature, public_key)

        try:
            key = Ed25519PublicKey.from_public_bytes(public_key[:32])
            key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
