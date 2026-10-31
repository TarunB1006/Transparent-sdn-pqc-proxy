"""Minimal OpenFlow 1.3 parsing for per-frame cipher selection.

Locates the Ethernet frame carried in PACKET_IN / PACKET_OUT messages by
walking the OpenFlow structure (rather than scanning for an Ethertype byte
pattern), and returns the inner IPv4 DSCP plus a 5-tuple flow key.

All other OpenFlow messages (FLOW_MOD, ECHO, FEATURES, STATS, ...) are
controller<->switch control messages; callers treat them as CS6 traffic.
"""

from __future__ import annotations

import struct
from typing import Optional, Tuple

OFPT_PACKET_IN = 10
OFPT_PACKET_OUT = 13

_ETH_IPV4 = 0x0800
_ETH_VLAN = (0x8100, 0x88A8)
_PROTO_PORTS = (6, 17, 132)   # TCP, UDP, SCTP


def _eth_payload_offset(msg: bytes) -> Optional[int]:
    """Offset of the Ethernet frame inside an OF1.3 PACKET_IN/PACKET_OUT."""
    if len(msg) < 24:
        return None
    of_type = msg[1]
    if of_type == OFPT_PACKET_IN:
        # header(8) buffer_id(4) total_len(2) reason(1) table_id(1) cookie(8)
        # then ofp_match (length at +2, padded to 8) then 2 pad bytes.
        if len(msg) < 28:
            return None
        match_len = struct.unpack_from("!H", msg, 26)[0]
        if match_len < 4:
            return None
        return 24 + ((match_len + 7) // 8) * 8 + 2
    if of_type == OFPT_PACKET_OUT:
        # header(8) buffer_id(4) in_port(4) actions_len(2) pad(6) actions data
        actions_len = struct.unpack_from("!H", msg, 16)[0]
        return 24 + actions_len
    return None


def parse_ipv4_flow(msg: bytes) -> Optional[Tuple[int, str]]:
    """Return (dscp, flow_key) for a PACKET_IN/PACKET_OUT carrying IPv4.

    Returns None for other message types, non-IPv4 payloads, or truncated
    frames.
    """
    eth = _eth_payload_offset(msg)
    if eth is None or eth + 14 > len(msg):
        return None
    ethertype = struct.unpack_from("!H", msg, eth + 12)[0]
    ip = eth + 14
    while ethertype in _ETH_VLAN:
        if ip + 4 > len(msg):
            return None
        ethertype = struct.unpack_from("!H", msg, ip + 2)[0]
        ip += 4
    if ethertype != _ETH_IPV4 or ip + 20 > len(msg):
        return None
    ver_ihl = msg[ip]
    if ver_ihl >> 4 != 4:
        return None
    dscp = msg[ip + 1] >> 2
    proto = msg[ip + 9]
    src = ".".join(str(b) for b in msg[ip + 12:ip + 16])
    dst = ".".join(str(b) for b in msg[ip + 16:ip + 20])
    sport = dport = 0
    frag = struct.unpack_from("!H", msg, ip + 6)[0] & 0x1FFF
    l4 = ip + (ver_ihl & 0x0F) * 4
    if proto in _PROTO_PORTS and frag == 0 and l4 + 4 <= len(msg):
        sport, dport = struct.unpack_from("!HH", msg, l4)
    return dscp, f"{src}:{sport}>{dst}:{dport}/{proto}"
