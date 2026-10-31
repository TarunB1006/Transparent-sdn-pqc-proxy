"""Hybrid TLS handshake (ML-KEM + ML-DSA-87 + AES-GCM)."""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from pqc_sdn.crypto.kem import Kem, KemVariant, KemKeyPair, parse_kem_variant
from pqc_sdn.crypto.signatures import SignatureKeyPair, SignatureScheme
from pqc_sdn.exceptions import HandshakeError
from pqc_sdn.tls.messages import (
    ClientAuth, ClientHello, ServerHello, Certificate, EncapsulatedKey,
)
from pqc_sdn.tls.session import SecureSession, derive_directional_keys

log = logging.getLogger(__name__)


@dataclass
class HandshakeResult:
    session: SecureSession
    shared_secret: bytes
    session_id: str
    kem_variant: str
    cipher_suite: str


class HybridHandshake:
    """
    Controller-switch handshake.

    Client generates a KEM keypair and sends the public key in ClientHello.
    Server encapsulates to that public key; both parties derive the same secret.
    """

    def __init__(
        self, entity_id: str, identity: Optional[SignatureKeyPair] = None
    ) -> None:
        self.entity_id = entity_id
        self._signer = SignatureScheme()
        # Only the responder signs. Its long-term identity is normally injected
        # (see pqc_sdn.tls.identity); otherwise it is generated lazily so the
        # initiator never pays for an unused ML-DSA-87 keygen.
        self._identity_kp: Optional[SignatureKeyPair] = identity
        self._transcript: List[bytes] = []
        self._client_kem: Optional[KemKeyPair] = None
        self._client_hello: Optional[ClientHello] = None
        # Set once the handshake completes; used for client authentication.
        self._transcript_hash: Optional[bytes] = None
        self._certificate_bytes: Optional[bytes] = None

    @property
    def _identity(self) -> SignatureKeyPair:
        if self._identity_kp is None:
            self._identity_kp = self._signer.keygen()
        return self._identity_kp

    @_identity.setter
    def _identity(self, value: SignatureKeyPair) -> None:
        self._identity_kp = value

    @property
    def identity_public_key(self) -> bytes:
        return self._identity.public_key

    def create_client_hello(self, variant: KemVariant = KemVariant.ML_KEM_1024) -> ClientHello:
        kem = Kem(variant)
        self._client_kem = kem.keygen()
        hello = ClientHello(
            sender_id=self.entity_id,
            ml_kem_variant=variant.value,
            kem_public_key=self._client_kem.public_key,
        )
        self._transcript.append(hello.serialize())
        self._client_hello = hello
        log.debug("[handshake] %s: ClientHello created variant=%s session=%s",
                  self.entity_id, variant.value, hello.session_id)
        return hello

    def server_respond(
        self, hello: ClientHello, allowed_variants: Optional[set] = None
    ) -> Tuple[ServerHello, Certificate, EncapsulatedKey, bytes]:
        if allowed_variants is not None and hello.ml_kem_variant not in allowed_variants:
            raise HandshakeError(
                f"KEM variant {hello.ml_kem_variant} not permitted by deployment policy"
            )
        self._transcript.append(hello.serialize())
        variant = parse_kem_variant(hello.ml_kem_variant)
        kem = Kem(variant)
        enc = kem.encapsulate(hello.kem_public_key)

        server_hello = ServerHello(
            sender_id=self.entity_id,
            session_id=hello.session_id,
            ml_kem_variant=variant.value,
        )
        self._transcript.append(server_hello.serialize())

        encap = EncapsulatedKey(
            ciphertext=enc.ciphertext,
            sender_id=self.entity_id,
            session_id=hello.session_id,
        )
        self._transcript.append(encap.serialize())

        # Sign the FULL transcript hash (m1 || m2 || m4), binding pk_e, n_C,
        # sid, V, c, and all server fields into the signature.  An attacker
        # who substitutes c' changes the hash, so sigma fails to verify.
        transcript_hash = hashlib.sha256(b"".join(self._transcript)).digest()
        cert_payload = b"pqc-sdn-handshake-v2|" + transcript_hash
        cert_sig = self._signer.sign(self._identity.secret_key, cert_payload)
        certificate = Certificate(
            issuer_id=self.entity_id,
            subject_id=self.entity_id,
            public_key=self._identity.public_key,
            signature=cert_sig,
        )

        log.debug("[handshake] %s: ServerHello created session=%s variant=%s",
                  self.entity_id, server_hello.session_id, variant.value)

        # Derive bound secret: HKDF over shared secret with transcript hash as salt.
        bound_secret = hashlib.sha256(enc.shared_secret + transcript_hash).digest()
        self._transcript_hash = transcript_hash
        self._certificate_bytes = certificate.serialize()

        return server_hello, certificate, encap, bound_secret

    def client_complete(
        self,
        server_hello: ServerHello,
        certificate: Certificate,
        encap: EncapsulatedKey,
        trusted_identity_key: Optional[bytes] = None,
    ) -> HandshakeResult:
        if self._client_kem is None:
            raise HandshakeError("create_client_hello must be called first")

        # Build the same transcript as the server: m1 (already appended in
        # create_client_hello), then m2 (ServerHello), then m4 (EncapsulatedKey).
        # Certificate is NOT part of the transcript hash — it carries the
        # signature OVER the transcript, not a message within it.
        self._transcript.extend(
            [server_hello.serialize(), encap.serialize()]
        )

        # Compute the transcript hash the server signed.
        transcript_hash = hashlib.sha256(b"".join(self._transcript)).digest()
        cert_payload = b"pqc-sdn-handshake-v2|" + transcript_hash

        # Verify the signature over the full transcript BEFORE decapsulating.
        # An attacker who substitutes c' changes the hash, so sigma fails here.
        if not self._signer.verify(
            certificate.public_key,
            cert_payload,
            certificate.signature,
        ):
            raise HandshakeError("certificate signature verification failed: transcript mismatch")

        # Certificate pinning: the certificate key must equal the pinned key
        # exactly (full-length, constant-time). Deployment code (sw_proxy_async)
        # makes pinning mandatory; None is accepted here only for unit tests and
        # for experiments that deliberately model an unpinned deployment.
        if trusted_identity_key is not None:
            if not hmac.compare_digest(certificate.public_key, trusted_identity_key):
                raise HandshakeError(
                    "certificate pinning failed: server identity does not match trusted key"
                )

        # Defense in depth: the responder must echo our session id and KEM
        # variant (both are already covered by the signed transcript hash).
        hello = self._client_hello
        if hello is not None and (
            server_hello.session_id != hello.session_id
            or encap.session_id != hello.session_id
            or server_hello.ml_kem_variant != hello.ml_kem_variant
        ):
            raise HandshakeError("server response does not match ClientHello")

        # Only now decapsulate — the transcript is authenticated.
        variant = parse_kem_variant(server_hello.ml_kem_variant)
        shared = Kem(variant).decapsulate_keypair(self._client_kem, encap.ciphertext)

        # Derive bound secret using the same transcript hash as the server.
        bound_secret = hashlib.sha256(shared + transcript_hash).digest()
        self._transcript_hash = transcript_hash
        self._certificate_bytes = certificate.serialize()

        send_key, recv_key = derive_directional_keys(bound_secret, server_hello.session_id)
        key_id = f"key-{server_hello.session_id}-{int(time.time())}"
        session = SecureSession(
            session_id=server_hello.session_id,
            send_key=send_key,
            recv_key=recv_key,
            key_id=key_id,
            local_id=self.entity_id,
            remote_id=server_hello.sender_id,
        )
        log.debug("[handshake] %s: client_complete OK session=%s variant=%s key=%s",
                  self.entity_id, server_hello.session_id, server_hello.ml_kem_variant, key_id)
        return HandshakeResult(
            session=session,
            shared_secret=shared,
            session_id=server_hello.session_id,
            kem_variant=server_hello.ml_kem_variant,
            cipher_suite=server_hello.selected_cipher,
        )

    # ── Client (switch-proxy) authentication ────────────────────────────────
    def _client_auth_payload(self) -> bytes:
        if self._transcript_hash is None or self._certificate_bytes is None:
            raise HandshakeError("handshake not complete")
        return (b"pqc-sdn-client-auth-v1|" + self._transcript_hash
                + hashlib.sha256(self._certificate_bytes).digest())

    def create_client_auth(self, identity: SignatureKeyPair) -> ClientAuth:
        """Initiator: sign the completed transcript (incl. the controller's
        certificate) with the switch-proxy identity key."""
        return ClientAuth(
            sender_id=self.entity_id,
            public_key=identity.public_key,
            signature=self._signer.sign(identity.secret_key, self._client_auth_payload()),
        )

    def verify_client_auth(self, auth: ClientAuth, authorized_keys) -> None:
        """Responder: accept only an authorized key with a valid signature over
        this session's transcript. Raises HandshakeError otherwise."""
        if not any(hmac.compare_digest(auth.public_key, k) for k in authorized_keys):
            raise HandshakeError("client authentication failed: key not authorized")
        if not self._signer.verify(auth.public_key, self._client_auth_payload(),
                                   auth.signature):
            raise HandshakeError("client authentication failed: bad signature")

    def transcript_hash(self) -> bytes:
        """SHA-256 over the concatenated serialized handshake messages."""
        return hashlib.sha256(b"".join(self._transcript)).digest()

    # Legacy alias for backward compatibility with tests.
    def transcript_mac(self, shared_secret: bytes) -> bytes:
        digest = self.transcript_hash()
        return hmac.new(shared_secret, digest, hashlib.sha256).digest()
