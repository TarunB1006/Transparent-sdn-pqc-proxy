"""Controller-side proxy placement plans."""

from __future__ import annotations

import logging
import threading
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Dict, List, Tuple

from pqc_sdn.channel.registry import SessionRegistry
from pqc_sdn.tls.session import SecureSession

log = logging.getLogger(__name__)


class ProxyRole(str, Enum):
    TUNNEL = "tunnel"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


@dataclass
class ProxyPlan:
    ctx: str
    role: ProxyRole
    peer: str
    algorithm: str
    dscp: int
    active: bool
    send_key_hex: str
    recv_key_hex: str
    key_id: str

    def to_dict(self) -> dict:
        """Full dict including keys — for internal proxy use only."""
        d = asdict(self)
        d["role"] = self.role.value
        return d

    def to_safe_dict(self) -> dict:
        """Redacted dict for API responses — keys are never exposed."""
        d = asdict(self)
        d["role"] = self.role.value
        d["send_key_hex"] = "[REDACTED]"
        d["recv_key_hex"] = "[REDACTED]"
        return d


class ProxyOrchestrator:
    """Decides which switch proxies encrypt/decrypt and publishes plans."""

    def __init__(self, registry: SessionRegistry) -> None:
        self._registry = registry
        self._lock = threading.RLock()
        self._plans: Dict[int, List[ProxyPlan]] = {}

    def plans_for_switch(self, dpid: int) -> List[dict]:
        """Return plans for API responses — keys redacted."""
        with self._lock:
            return [p.to_safe_dict() for p in self._plans.get(dpid, [])]

    def plans_for_switch_internal(self, dpid: int) -> List[dict]:
        """Return plans with real keys — for internal proxy use only, NOT for APIs."""
        with self._lock:
            return [p.to_dict() for p in self._plans.get(dpid, [])]

    def all_plans(self) -> Dict[str, List[dict]]:
        """Return all plans for API responses — keys redacted."""
        with self._lock:
            return {str(k): [p.to_safe_dict() for p in v] for k, v in self._plans.items()}

    def _keys_hex(self, session: SecureSession) -> Tuple[str, str, str]:
        return session.send_key.hex(), session.recv_key.hex(), session.key_id

    def activate_control_plane(
        self, dpid: int, session: SecureSession, algorithm: str = "ML-KEM-1024"
    ) -> None:
        ctx = f"switch:{dpid}"
        self._registry.register(ctx, session, algorithm=algorithm, role="tunnel")
        sk, rk, kid = self._keys_hex(session)
        plan = ProxyPlan(
            ctx=ctx,
            role=ProxyRole.TUNNEL,
            peer="controller",
            algorithm=algorithm,
            dscp=48,
            active=True,
            send_key_hex=sk,
            recv_key_hex=rk,
            key_id=kid,
        )
        with self._lock:
            self._plans[dpid] = [plan]
        log.info("[orchestrator] control plane active sw-%d ctx=%s", dpid, ctx)

    def activate_path(
        self,
        path: List[int],
        flow_key: Tuple,
        algorithm: str,
        dscp: int,
    ) -> None:
        if len(path) < 2:
            return
            
        src, dst = path[0], path[-1]
        enc_ctx = f"flow:{flow_key}:enc"
        dec_ctx = f"flow:{flow_key}:dec"
        
        child = self._registry.derive_child(
            f"flow:{flow_key}:{src}:{dst}",
            f"switch:{src}",
            algorithm=algorithm,
            dscp=dscp,
            flow_tag=str(flow_key),
        )
        if child is None:
            return
            
        sk, rk, kid = self._keys_hex(child)
        self._append(
            src,
            ProxyPlan(
                enc_ctx, ProxyRole.ENCRYPT, f"switch-{dst}",
                algorithm, dscp, True, sk, rk, kid,
            ),
        )
        self._append(
            dst,
            ProxyPlan(
                dec_ctx, ProxyRole.DECRYPT, f"switch-{src}",
                algorithm, dscp, True, rk, sk, kid,
            ),
        )
        log.debug(
            "[orchestrator] path %s flow=%s algo=%s dscp=%d",
            path, flow_key, algorithm, dscp,
        )

    def _append(self, dpid: int, plan: ProxyPlan) -> None:
        with self._lock:
            existing = self._plans.setdefault(dpid, [])
            if not any(p.ctx == plan.ctx for p in existing):
                existing.append(plan)

    def should_encrypt(self, dpid: int, ctx: str) -> bool:
        with self._lock:
            for p in self._plans.get(dpid, []):
                if p.ctx == ctx and p.active:
                    return p.role in (ProxyRole.TUNNEL, ProxyRole.ENCRYPT)
        return False

    def should_decrypt(self, dpid: int, ctx: str) -> bool:
        with self._lock:
            for p in self._plans.get(dpid, []):
                if p.ctx == ctx and p.active:
                    return p.role in (ProxyRole.TUNNEL, ProxyRole.DECRYPT)
        return False

    def cleanup_flow_plans(self, max_per_switch: int = 100) -> int:
        """Remove excess flow-level plans per switch to prevent memory leaks.

        Keeps tunnel plans and the most recent `max_per_switch` flow plans.
        Returns the number of plans removed.
        """
        removed = 0
        with self._lock:
            for dpid, plans in self._plans.items():
                tunnels = [p for p in plans if p.role == ProxyRole.TUNNEL]
                flows = [p for p in plans if p.role != ProxyRole.TUNNEL]
                if len(flows) > max_per_switch:
                    excess = len(flows) - max_per_switch
                    plans[:] = tunnels + flows[excess:]
                    removed += excess
        return removed
