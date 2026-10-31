"""Session registry and pqc_encrypt / pqc_decrypt API."""

from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from pqc_sdn.exceptions import SessionError

log = logging.getLogger(__name__)
from pqc_sdn.tls.session import SecurePacket, SecureSession


@dataclass
class SessionRecord:
    session: SecureSession
    algorithm: str
    dscp: int = 0
    role: str = "tunnel"


class SessionRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: Dict[str, SessionRecord] = {}

    def register(
        self,
        ctx: str,
        session: SecureSession,
        *,
        algorithm: str,
        dscp: int = 0,
        role: str = "tunnel",
    ) -> None:
        with self._lock:
            self._sessions[ctx] = SessionRecord(session, algorithm, dscp, role)
            log.debug("[registry] registered ctx=%s algo=%s role=%s (total=%d)",
                      ctx, algorithm, role, len(self._sessions))

    def get(self, ctx: str) -> Optional[SecureSession]:
        with self._lock:
            rec = self._sessions.get(ctx)
            return rec.session if rec else None

    def get_record(self, ctx: str) -> Optional[SessionRecord]:
        with self._lock:
            return self._sessions.get(ctx)

    def unregister(self, ctx: str) -> None:
        with self._lock:
            self._sessions.pop(ctx, None)

    def active_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def derive_child(
        self,
        child_ctx: str,
        parent_ctx: str,
        *,
        algorithm: str,
        dscp: int,
        flow_tag: str,
    ) -> Optional[SecureSession]:
        parent = self.get(parent_ctx)
        if parent is None or not parent.is_active:
            return None
        info = f"{child_ctx}:{flow_tag}:dscp:{dscp}".encode()
        send = hashlib.sha256(parent.send_key + info).digest()
        recv = hashlib.sha256(parent.recv_key + info).digest()
        child = SecureSession(
            session_id=f"{parent.session_id}-{child_ctx}",
            send_key=send,
            recv_key=recv,
            key_id=f"{parent.key_id}-child",
            local_id=parent.local_id,
            remote_id=parent.remote_id,
        )
        self.register(child_ctx, child, algorithm=algorithm, dscp=dscp, role="flow")
        return child


_registry = SessionRegistry()


def get_registry() -> SessionRegistry:
    return _registry


def get_session(ctx: str) -> Optional[SecureSession]:
    return _registry.get(ctx)


def pqc_encrypt(ctx: str, plaintext: bytes, aad: Optional[bytes] = None) -> SecurePacket:
    session = _registry.get(ctx)
    if session is None or not session.is_active:
        raise SessionError(f"no active session for ctx={ctx!r}")
    return session.encrypt(plaintext, aad=aad)


def pqc_decrypt(ctx: str, packet: SecurePacket) -> bytes:
    session = _registry.get(ctx)
    if session is None or not session.is_active:
        raise SessionError(f"no active session for ctx={ctx!r}")
    return session.decrypt(packet)
