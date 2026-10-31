"""
pqc_sdn/routing/qos_router.py — Latency-Optimal Path Selection for Critical Traffic

Implements Dijkstra's algorithm weighted by measured RTT (from Echo-Request probing)
for DSCP EF (tag 46) traffic.  Non-EF traffic continues to use WeightedECMPRouter.

Design
------
- Edge weights = measured RTT in milliseconds (from controller.latency_map).
- Infinity RTT (link down or unprobed) → link excluded from graph.
- Does NOT replace ecmp.py.  Both coexist; controller.py dispatches by DSCP.
- Thread-safe: NetworkX graph is rebuilt per call (no shared mutable state).

ACADEMIC CAVEAT
---------------
Echo-Request RTT measures control-plane latency (Controller ↔ Switch proxy),
NOT physical data-plane link latency between two switches.  This metric reflects
cryptographic processing load and proxy congestion at the switch, used as a
routing weight under stress.  True physical link latency requires LLDP timestamp
probes (tagged as future work).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import networkx as nx


def get_latency_path(
    src_dpid: int,
    dst_dpid: int,
    latency_map: Dict[Tuple[int, int], float],
) -> Optional[List[int]]:
    """
    Return the latency-optimal (Dijkstra) path from src_dpid to dst_dpid.

    Parameters
    ----------
    src_dpid     : Source switch DPID.
    dst_dpid     : Destination switch DPID.
    latency_map  : Mapping (src_dpid, dst_dpid) → RTT in milliseconds.
                   float('inf') or missing means the link is excluded.

    Returns
    -------
    Ordered list of DPIDs, or None if unreachable.

    Example
    -------
    >>> latency_map = {('A','B'): 5, ('B','D'): 3, ('A','C'): 2, ('C','D'): 10}
    >>> get_latency_path('A', 'D', latency_map)
    ['A', 'B', 'D']   # total 8ms < A→C→D 12ms
    """
    if src_dpid == dst_dpid:
        return [src_dpid]

    g = nx.DiGraph()

    for (u, v), rtt_ms in latency_map.items():
        if rtt_ms is not None and rtt_ms != float("inf") and rtt_ms > 0:
            g.add_edge(u, v, weight=rtt_ms)

    if not g.has_node(src_dpid) or not g.has_node(dst_dpid):
        return None

    try:
        path = nx.dijkstra_path(g, src_dpid, dst_dpid, weight="weight")
        return path
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None
