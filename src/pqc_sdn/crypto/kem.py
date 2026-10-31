"""ML-KEM (FIPS 203) key encapsulation."""

from __future__ import annotations

import enum
import logging
import os
from dataclasses import dataclass, field
from typing import Dict

from pqc_sdn.exceptions import CryptoError

logger = logging.getLogger(__name__)

try:
    import oqs

    _LIBOQS = True
except ImportError:
    _LIBOQS = False
    import os as _os
    if _os.environ.get("PQC_INSECURE_DEV_FALLBACK", "0") != "1":
        raise ImportError(
            "liboqs is required for post-quantum security. "
            "Set PQC_INSECURE_DEV_FALLBACK=1 to use the classical X25519 fallback "
            "(NOT suitable for production)."
        )
    import warnings
    warnings.warn(
        "liboqs not available — using INSECURE X25519/Ed25519 classical fallback. "
        "This provides NO post-quantum security.",
        stacklevel=2,
    )
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Post-quantum backend (default "liboqs"). "openssl" uses the FIPS 203 implementation in OpenSSL
# (via pyca/cryptography >= 47) for ML-KEM-768/1024; ML-KEM-512 is not exposed
# there and always uses liboqs. "liboqs" forces liboqs for every parameter set.
# Wire encodings (public keys, ciphertexts) are identical across backends.
try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem
    _OPENSSL_KEM = {
        "ML-KEM-768": _mlkem.MLKEM768PrivateKey,
        "ML-KEM-1024": _mlkem.MLKEM1024PrivateKey,
    }
    _OPENSSL_KEM_PUB = {
        "ML-KEM-768": _mlkem.MLKEM768PublicKey,
        "ML-KEM-1024": _mlkem.MLKEM1024PublicKey,
    }
except ImportError:  # older cryptography
    _OPENSSL_KEM, _OPENSSL_KEM_PUB = {}, {}

_OPENSSL_SEED_LEN = 64   # d || z seed; liboqs secret keys are the expanded form


def pq_backend() -> str:
    return os.environ.get("PQC_PQ_BACKEND", "liboqs")


class KemVariant(enum.Enum):
    ML_KEM_512 = "ML-KEM-512"
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"


@dataclass(frozen=True)
class KemParams:
    public_key_size: int
    secret_key_size: int
    ciphertext_size: int
    shared_secret_size: int
    quantum_security_bits: int


KEM_PARAMS: Dict[KemVariant, KemParams] = {
    KemVariant.ML_KEM_512: KemParams(800, 1632, 768, 32, 128),
    KemVariant.ML_KEM_768: KemParams(1184, 2400, 1088, 32, 192),
    KemVariant.ML_KEM_1024: KemParams(1568, 3168, 1568, 32, 256),
}

_OQS_NAMES = {v: v.value for v in KemVariant}


@dataclass(frozen=True)
class KemKeyPair:
    public_key: bytes
    secret_key: bytes
    variant: KemVariant
    # Expanded backend key object, kept so decapsulation needs no re-expansion.
    handle: object = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class KemEncapsulation:
    ciphertext: bytes
    shared_secret: bytes


class Kem:
    """ML-KEM encapsulation with liboqs or documented classical fallback."""

    def __init__(self, variant: KemVariant) -> None:
        self._variant = variant
        self._params = KEM_PARAMS[variant]
        logger.debug("[kem] init variant=%s backend=%s",
                     variant.value, "liboqs" if _LIBOQS else "X25519-fallback")

    @property
    def variant(self) -> KemVariant:
        return self._variant

    @property
    def uses_liboqs(self) -> bool:
        return _LIBOQS and not self._openssl

    @property
    def _openssl(self) -> bool:
        return pq_backend() == "openssl" and self._variant.value in _OPENSSL_KEM

    @property
    def backend(self) -> str:
        if self._openssl:
            return "openssl"
        return "liboqs" if _LIBOQS else "X25519-fallback"

    def keygen(self) -> KemKeyPair:
        if self._openssl:
            priv = _OPENSSL_KEM[self._variant.value].generate()
            return KemKeyPair(priv.public_key().public_bytes_raw(),
                              priv.private_bytes_raw(), self._variant, priv)
        if _LIBOQS:
            alg = _OQS_NAMES[self._variant]
            with oqs.KeyEncapsulation(alg) as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()
            return KemKeyPair(public_key, secret_key, self._variant)

        private = X25519PrivateKey.generate()
        public = private.public_key()
        pk = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sk = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return KemKeyPair(
            self._pad(pk, self._params.public_key_size),
            self._pad(sk, self._params.secret_key_size),
            self._variant,
        )

    def encapsulate(self, recipient_public_key: bytes) -> KemEncapsulation:
        if self._openssl:
            pub = _OPENSSL_KEM_PUB[self._variant.value].from_public_bytes(recipient_public_key)
            shared_secret, ciphertext = pub.encapsulate()
            return KemEncapsulation(ciphertext, shared_secret)
        if _LIBOQS:
            alg = _OQS_NAMES[self._variant]
            with oqs.KeyEncapsulation(alg) as kem:
                ciphertext, shared_secret = kem.encap_secret(recipient_public_key)
            return KemEncapsulation(ciphertext, shared_secret)

        pk = X25519PublicKey.from_public_bytes(recipient_public_key[:32])
        ephemeral = X25519PrivateKey.generate()
        shared = ephemeral.exchange(pk)
        ct = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        padded_ct = self._pad(ct, self._params.ciphertext_size)
        # Bind the ENTIRE ciphertext (including padding) into the KDF
        # so both sides derive the same secret from the same ciphertext bytes.
        import hashlib
        ct_binding = hashlib.sha256(padded_ct).digest()
        secret = HKDF(
            algorithm=hashes.SHA256(),
            length=self._params.shared_secret_size,
            salt=ct_binding,
            info=self._variant.value.encode(),
        ).derive(shared)
        return KemEncapsulation(padded_ct, secret)

    def decapsulate_keypair(self, keypair: KemKeyPair, ciphertext: bytes) -> bytes:
        """Decapsulate with a keypair from keygen(), reusing its expanded key."""
        if keypair.handle is not None:
            return keypair.handle.decapsulate(ciphertext)
        return self.decapsulate(keypair.secret_key, ciphertext)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        if len(secret_key) == _OPENSSL_SEED_LEN and self._variant.value in _OPENSSL_KEM:
            priv = _OPENSSL_KEM[self._variant.value].from_seed_bytes(secret_key)
            return priv.decapsulate(ciphertext)
        if _LIBOQS:
            alg = _OQS_NAMES[self._variant]
            with oqs.KeyEncapsulation(alg, secret_key=secret_key) as kem:
                return kem.decap_secret(ciphertext)

        private = X25519PrivateKey.from_private_bytes(secret_key[:32])
        ephemeral_pk = X25519PublicKey.from_public_bytes(ciphertext[:32])
        shared = private.exchange(ephemeral_pk)
        # Bind the ENTIRE ciphertext into the KDF so mutations to any byte
        # (including padding beyond byte 32) change the derived secret.
        # This provides IND-CCA2-like implicit rejection for the classical fallback.
        import hashlib
        ct_binding = hashlib.sha256(ciphertext).digest()
        return HKDF(
            algorithm=hashes.SHA256(),
            length=self._params.shared_secret_size,
            salt=ct_binding,
            info=self._variant.value.encode(),
        ).derive(shared)

    @staticmethod
    def _pad(data: bytes, size: int) -> bytes:
        if len(data) >= size:
            return data[:size]
        return data + os.urandom(size - len(data))


def verify_kem_algorithms() -> bool:
    """Return True if all ML-KEM variants are available in liboqs."""
    if not _LIBOQS:
        logger.warning("liboqs not installed — using classical KEM simulation")
        return False
    enabled = set(oqs.get_enabled_kem_mechanisms())
    missing = [v.value for v in KemVariant if v.value not in enabled]
    if missing:
        logger.error("Missing ML-KEM in liboqs build: %s", missing)
        return False
    return True


def parse_kem_variant(name: str) -> KemVariant:
    try:
        return KemVariant(name)
    except ValueError as exc:
        raise CryptoError(f"Unknown KEM variant: {name}") from exc
