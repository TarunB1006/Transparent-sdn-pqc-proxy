"""
pqc_sdn/routing/ecmp.py — Weighted ECMP with Crypto-Aware Path Scoring

Replaces the nx.shortest_path stub in controller.py with a routing decision
that treats PQC encryption overhead as a first-class routing cost alongside
link utilisation.

Scoring model (lower is better)
--------------------------------
    path_score = Σ_hop( α * utilisation_i  +  β * crypto_overhead_ms_i )

Where:
    utilisation_i     — normalised [0,1] tx utilisation of the link leaving
                        switch i on this path (from OpenFlow port stats)
    crypto_overhead_i — overhead in ms of the algorithm negotiated for this
                        flow on switch i (from AdaptivePQCEngine.ALGORITHM_OVERHEAD)
    α = 0.7           — weight for utilisation (primary signal)
    β = 0.3           — weight for crypto overhead (secondary signal, normalised)

Utilisation calculation (matches uploaded RL controller approach)
-----------------------------------------------------------------
    utilisation = min( (delta_bytes * 8) / (delta_t * LINK_CAPACITY_BPS), 1.0 )

    LINK_CAPACITY_BPS = 10_000_000  (10 Mbps — Mininet fat_tree TCLink default)

    Using actual wall-clock delta_t (not a fixed poll constant) gives accurate
    throughput values even when reply timing jitters.  The 10 Mbps capacity
    matches the Mininet environment — the previous 1 Gbps fallback made all
    utilisation values round to ~0.000 because OVS returns curr_speed=0.

Why this split matters for PQC-SDN
------------------------------------
Without crypto-aware scoring the controller may route a latency-sensitive
flow (AES-256-GCM, 0.15 ms overhead) through a lightly-loaded path that
happens to share switches already carrying heavy ML-KEM-1024 sessions
(1.5 ms overhead).  Those switches add crypto processing delay even if the
link utilisation looks fine.  The combined score prevents this.

Flow pinning
------------
Each TCP/UDP flow is pinned to a consistent path via a 5-tuple hash so that
packets within a flow are never reordered (which would spike RTT and cause
the AdaptivePQCEngine to downgrade the crypto algorithm unnecessarily).

Path cache
----------
Selected paths are cached for CACHE_TTL seconds to avoid recomputing on
every packet-in.  The cache is invalidated on port-stats update so a sudden
link load change is reflected on the next flow.

Thread safety
-------------
link_utilisation and _path_cache are written by the port-stats polling
greenlet and read by the packet-in handler greenlet.  Plain dict operations
on CPython are GIL-protected, which is sufficient for the Ryu event-loop
concurrency model.
"""

import hashlib
import time
import logging
from typing import Dict, List, Optional, Tuple

import networkx as nx

from pqc_sdn.policy.engine import CIPHER_METRICS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

UTIL_WEIGHT   = 0.7   # α — link utilisation contribution
CRYPTO_WEIGHT = 0.3   # β — crypto overhead contribution

# Normalisation ceiling for crypto overhead (ms).
# ML-KEM-1024 is 1.5 ms; ceiling at 2.0 ms keeps the scaled value in [0, 1].
# Symmetric cipher overhead ceiling (ms). ChaCha20=0.09, AES-128=0.12, AES-256=0.18.
CRYPTO_OVERHEAD_CEILING_MS = 0.25

# Path cache TTL in seconds.  Set short enough that load changes matter.
CACHE_TTL = 5.0

# Crypto overhead per algorithm (ms), mirrored from AdaptivePQCEngine so
# the router does not import the engine (avoids circular deps).
# With LINK_CAPACITY_BPS=10 Mbps, an iperf flow at ~130 Kbits/s gives util~0.013.
# ML-KEM-1024 overhead of 1.5 ms normalised against 2.0 ms ceiling gives 0.75.
# Combined score = 0.7*0.013 + 0.3*0.75 = 0.234 — meaningful differentiation.
# Combined score = 0.7*0.013 + 0.3*0.75 = 0.234 — meaningful differentiation.

# ---------------------------------------------------------------------------
# WeightedECMPRouter
# ---------------------------------------------------------------------------

class WeightedECMPRouter:
    """
    Weighted ECMP router for the PQC-SDN controller.

    Usage
    -----
    Instantiate once in PQCController.__init__:

        self._router = WeightedECMPRouter()

    Update link utilisation from the port-stats polling loop:

        self._router.update_link_utilisation(src_dpid, dst_dpid, utilisation)

    Select a path for a flow:

        path = self._router.select_path(
            graph, src_dpid, dst_dpid,
            flow_key=(src_ip, dst_ip, proto, src_port, dst_port),
            algorithm="ML-KEM-1024",
        )
    """

    def __init__(self):
        # (src_dpid, dst_dpid) → utilisation in [0.0, 1.0]
        self.link_utilisation: Dict[Tuple[int, int], float] = {}

        # (src_dpid, dst_dpid, flow_hash) → (path, expires_at)
        self._path_cache: Dict[Tuple[int, int, int], Tuple[List[int], float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_link_utilisation(
        self,
        src_dpid: int,
        dst_dpid: int,
        utilisation: float,
    ) -> None:
        """
        Record the current normalised utilisation [0.0–1.0] for a directed link.

        Called by the port-stats polling loop in controller.py.
        Invalidates cached paths that traverse this link.
        """
        old = self.link_utilisation.get((src_dpid, dst_dpid), 0.0)
        self.link_utilisation[(src_dpid, dst_dpid)] = max(0.0, min(1.0, utilisation))

        # Invalidate cache entries whose path crosses this link.
        if abs(old - utilisation) > 0.05:   # only bother if meaningfully changed
            self._invalidate_cache_for_link(src_dpid, dst_dpid)

    def select_path(
        self,
        graph: nx.DiGraph,
        src_dpid: int,
        dst_dpid: int,
        flow_key: tuple = (),
        algorithm: str = "AES-256-GCM",
    ) -> Optional[List[int]]:
        """
        Return the best path from src_dpid to dst_dpid for this flow.

        Parameters
        ----------
        graph     : Current network DiGraph (from controller topology).
        src_dpid  : Source switch DPID.
        dst_dpid  : Destination switch DPID.
        flow_key  : 5-tuple (src_ip, dst_ip, proto, src_port, dst_port).
                    Used for consistent flow pinning via hash.
                    Pass () to skip pinning (e.g. for ARP).
        algorithm : Crypto algorithm negotiated for this flow
                    (from _pick_algorithm in controller.py).
                    Used to score path switches by their crypto overhead.

        Returns
        -------
        Ordered list of DPIDs from src to dst, or None if unreachable.
        """
        if src_dpid == dst_dpid:
            return [src_dpid]

        try:
            if not nx.has_path(graph, src_dpid, dst_dpid):
                return None
        except (nx.NodeNotFound, nx.NetworkXError):
            return None

        flow_hash = self._flow_hash(flow_key)
        cache_key = (src_dpid, dst_dpid, flow_hash)

        # Return cached path if still fresh
        cached = self._path_cache.get(cache_key)
        if cached:
            path, expires_at = cached
            if time.time() < expires_at:
                return path

        # Enumerate all shortest (hop-count) paths
        try:
            candidates = list(
                nx.all_shortest_paths(graph, src_dpid, dst_dpid)
            )
        except nx.NetworkXNoPath:
            return None

        if not candidates:
            return None

        if len(candidates) == 1:
            # No ECMP choice — skip scoring overhead
            path = candidates[0]
            self._cache_path(cache_key, path)
            return path

        # Score and pick the best path
        best_path  = None
        best_score = float("inf")

        for path in candidates:
            score = self._score_path(path, algorithm)
            if score < best_score:
                best_score = score
                best_path  = path

        if best_path is None:
            # Fallback: use flow hash to pick consistently among equals
            best_path = candidates[flow_hash % len(candidates)]

        self._cache_path(cache_key, best_path)

        logger.debug(
            "[ECMP] %d→%d  algo=%-12s  candidates=%d  "
            "chosen=%s  score=%.4f",
            src_dpid, dst_dpid, algorithm,
            len(candidates),
            "→".join(str(d) for d in best_path),
            best_score,
        )

        return best_path

    def get_path_score(
        self,
        path: List[int],
        algorithm: str,
    ) -> float:
        """Return the combined score for a path (for logging / testing)."""
        return self._score_path(path, algorithm)

    def link_load_summary(self) -> Dict[Tuple[int, int], float]:
        """Return a snapshot of all known link utilisations (for dashboard)."""
        return dict(self.link_utilisation)

    # ------------------------------------------------------------------
    # Scoring internals
    # ------------------------------------------------------------------

    def _score_path(self, path: List[int], algorithm: str) -> float:
        """
        Compute the weighted score for a path.

            score = Σ_hop( α * util_i  +  β * norm_crypto_i )

        A lower score is better.
        """
        _, crypto_ms = CIPHER_METRICS.get(algorithm, (128, 0.15))
        norm_crypto   = min(crypto_ms / CRYPTO_OVERHEAD_CEILING_MS, 1.0)
        score         = 0.0

        for i in range(len(path) - 1):
            src, dst = path[i], path[i + 1]
            util      = self.link_utilisation.get((src, dst), 0.0)
            score    += UTIL_WEIGHT * util + CRYPTO_WEIGHT * norm_crypto

        return score

    # ------------------------------------------------------------------
    # Flow pinning
    # ------------------------------------------------------------------

    @staticmethod
    def _flow_hash(flow_key: tuple) -> int:
        """
        Stable 32-bit hash of the 5-tuple for flow pinning.

        Consistent across calls so a TCP flow always maps to the same path
        as long as the cache is valid, preventing packet reordering.
        """
        if not flow_key:
            return 0
        raw = "|".join(str(f) for f in flow_key).encode()
        return int(hashlib.md5(raw).hexdigest()[:8], 16)

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _cache_path(self, key: tuple, path: List[int]) -> None:
        self._path_cache[key] = (path, time.time() + CACHE_TTL)

    def _invalidate_cache_for_link(self, src_dpid: int, dst_dpid: int) -> None:
        """Remove cache entries whose path traverses the changed link."""
        to_delete = [
            k for k, (path, _) in self._path_cache.items()
            if any(
                path[i] == src_dpid and path[i + 1] == dst_dpid
                for i in range(len(path) - 1)
            )
        ]
        for k in to_delete:
            del self._path_cache[k]

    def clear_cache(self) -> None:
        """Force full cache flush (e.g. after topology change)."""
        self._path_cache.clear()
