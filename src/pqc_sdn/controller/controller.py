"""
controller.py — PQC-SDN Ryu Application Adapter

This module bridges the Ryu OpenFlow event loop with the framework-agnostic
ControlPlaneService and the legacy WeightedECMPRouter.

Usage:
    ryu-manager src/pqc_sdn/controller/controller.py --observe-links --verbose
"""

import os
import sys
import time
import threading

import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
from ryu.topology import api as topo_api
from ryu.topology.api import get_all_switch, get_link
from ryu.lib import hub

# Inject the platform root to sys.path so Ryu can find the pqc_sdn package
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _SRC_ROOT not in sys.path:
    sys.path.insert(0, _SRC_ROOT)

from pqc_sdn.settings import get_settings
from pqc_sdn.controller.control_plane import ControlPlaneService
from pqc_sdn.routing.ecmp import WeightedECMPRouter
from pqc_sdn.metrics.exporter import (
    MetricsExporter, PACKET_IN_SECONDS, PQC_OVERHEAD_BYTES, PQC_ACTIVE_SESSIONS,
    THROUGHPUT_BPS, LINK_UTILIZATION,
    PQC_HANDSHAKE_FAILURES, PQC_DOWNGRADE_ATTEMPTS, PQC_DOS_PACKET_IN_RATE,
    PQC_CONTROLLER_CPU_PERCENT, PQC_CONTROLLER_MEMORY_BYTES,
)
from pqc_sdn.apps import plan_api


class PQCAdapter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.settings = get_settings()
        self.link_capacity = self.settings.routing.link_capacity_bps

        # ── PQC Control Plane & API ─────────────────────────────────────────
        self.service = ControlPlaneService(controller_id="sdn-controller")
        plan_api._SERVICE = self.service
        
        api_host = self.settings.proxy.controller_host
        api_port = self.settings.proxy.controller_api_port
        threading.Thread(
            target=plan_api.serve, 
            args=(api_host, api_port), 
            daemon=True
        ).start()
        
        # ── Metrics ─────────────────────────────────────────────────────────
        # SIN 3 FIXED: Use configured metrics port (9101) instead of hardcoded 8000
        self.exporter = MetricsExporter(self.settings.metrics.host, self.settings.metrics.port)
        try:
            self.exporter.start()
        except OSError as e:
            self.logger.warning("[PQC-SDN] Metrics server failed to start (%s) — continuing without metrics", e)

        # ── Topology & Routing state ────────────────────────────────────────
        self.graph = nx.DiGraph()
        self.dps = {}
        self.link_to_port = {}
        self.access_table = {}
        self.switch_port_table = {}
        self.interior_ports = {}
        self.access_ports = {}

        self.router = WeightedECMPRouter()
        
        # SIN 1 FIXED: State tracking for port utilisation calculation
        self._port_stats_prev = {} # (dpid, port_no) -> (tx_bytes, time)
        # DoS rate tracking: dpid -> (count, window_start)
        self._packet_in_rate: dict = {}

        # ── Background threads ──────────────────────────────────────────────
        hub.spawn(self._discover_topology)
        hub.spawn(self._port_stats_loop)

        self.logger.info("[PQC-SDN] Ryu Adapter Initialized.")

    # =========================================================================
    # TOPOLOGY DISCOVERY
    # =========================================================================

    def _discover_topology(self):
        while True:
            hub.sleep(1)
            sw_list = get_all_switch(self)
            self._build_port_map(sw_list)
            links = get_link(self, None)
            self._build_interior_links(links)
            self._build_access_ports()
            self._build_graph()

    def _build_port_map(self, sw_list):
        for sw in sw_list:
            dpid = sw.dp.id
            self.graph.add_node(dpid)
            self.dps[dpid] = sw.dp
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())
            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def _build_interior_links(self, link_list):
        for link in link_list:
            src, dst = link.src, link.dst
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            if src.dpid in self.switch_port_table:
                self.interior_ports[src.dpid].add(src.port_no)
            if dst.dpid in self.switch_port_table:
                self.interior_ports[dst.dpid].add(dst.port_no)

    def _build_access_ports(self):
        for dpid in self.switch_port_table:
            self.access_ports[dpid] = (
                self.switch_port_table[dpid] - self.interior_ports[dpid]
            )

    def _build_graph(self):
        for link in topo_api.get_all_link(self):
            self.graph.add_edge(
                link.src.dpid, link.dst.dpid,
                src_port=link.src.port_no,
                dst_port=link.dst.port_no,
            )

    # =========================================================================
    # SWITCH CONNECT -> Hybrid TLS Handshake
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        self.dps[dpid] = dp

        # Table-miss: send unmatched packets to controller
        self._add_flow(dp, 0, parser.OFPMatch(),
                       [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                               ofproto.OFPCML_NO_BUFFER)], idle_timeout=0)
        # Drop IPv6
        self._add_flow(dp, 65534,
                       parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6), [], idle_timeout=0)

        # Legacy plan-poll mode only: simulate the PQC handshake in-process and
        # publish a plan. In the default handshake-first deployment the proxies
        # perform the real handshake, so this is skipped.
        if get_settings().controller.inprocess_handshake and not self.service.get_session(dpid):
            self.logger.info(f"[RYU] switch-{dpid} connected — delegating to ControlPlaneService")
            success = self.service.on_switch_connected(dpid)
            if success:
                self.logger.info(f"[RYU] switch-{dpid} ML-KEM handshake complete.")
                PQC_ACTIVE_SESSIONS.set(len(self.service._switch_sessions))
            else:
                self.logger.warning(f"[RYU] switch-{dpid} ML-KEM handshake failed.")
                PQC_HANDSHAKE_FAILURES.labels(dpid=str(dpid), reason="handshake_error").inc()

    # SIN 2 FIXED: Support idle_timeout for flows
    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=10):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst,
                                    idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    # =========================================================================
    # PACKET-IN (ARP & IPv4)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        t0 = time.perf_counter()
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        dpid = dp.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Ensure the dpid is tracked even before full topology discovery
        self.switch_port_table.setdefault(dpid, set()).add(in_port)

        if arp_pkt:
            self._register_host(dpid, in_port, arp_pkt.src_ip, arp_pkt.src_mac)
            self._arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if ip_pkt:
            self._register_host(dpid, in_port, ip_pkt.src, eth.src)
            self._ip_forwarding(msg, eth.ethertype, ip_pkt.src, ip_pkt.dst, ip_pkt)

        elapsed = time.perf_counter() - t0
        PACKET_IN_SECONDS.labels(dpid=str(dpid)).observe(elapsed)

        # DoS rate tracking — update packets/s gauge
        now = time.time()
        count, window = self._packet_in_rate.get(dpid, (0, now))
        dt = now - window
        if dt >= 1.0:
            PQC_DOS_PACKET_IN_RATE.labels(dpid=str(dpid)).set(count / max(dt, 1.0))
            self._packet_in_rate[dpid] = (1, now)
        else:
            self._packet_in_rate[dpid] = (count + 1, window)

    def _register_host(self, dpid: int, in_port: int, ip: str, mac: str):
        # Only register hosts on access (host-facing) ports.
        # Interior ports carry switch-to-switch traffic; registering hosts there
        # causes ARP-flood artifacts that corrupt the host location table.
        known_interior = self.interior_ports.get(dpid)
        if known_interior and in_port in known_interior:
            return
        entry = (ip, mac)
        if self.access_table.get((dpid, in_port)) != entry:
            self.access_table[(dpid, in_port)] = entry
            self.logger.debug(f"[HOST] {ip} ({mac}) joined sw-{dpid} port {in_port}")
            self.service.on_device_onboard(mac)

    def _get_host_location(self, ip: str):
        for (dpid, port), (h_ip, _) in self.access_table.items():
            if h_ip == ip:
                return (dpid, port)
        return None

    def _arp_forwarding(self, msg, src_ip: str, dst_ip: str):
        dp = msg.datapath
        ofproto = dp.ofproto
        in_port = msg.match['in_port']
        location = self._get_host_location(dst_ip)
        if location:
            dst_dpid, out_port = location
            if dst_dpid in self.dps:
                out_dp = self.dps[dst_dpid]
                out = self._build_packet_out(out_dp, ofproto.OFP_NO_BUFFER,
                                             ofproto.OFPP_CONTROLLER, out_port, msg.data)
                out_dp.send_msg(out)
                return
        self._flood(msg)

    def _flood(self, msg):
        """Flood via the originating switch using OFPP_FLOOD — no topology knowledge needed."""
        dp = msg.datapath
        ofproto = dp.ofproto
        in_port = msg.match['in_port']
        out = self._build_packet_out(dp, msg.buffer_id, in_port, ofproto.OFPP_FLOOD, msg.data)
        dp.send_msg(out)

    def _build_packet_out(self, datapath, buffer_id, in_port, out_port, data):
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        return datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id, in_port=in_port,
            actions=actions, data=data)

    def _ip_forwarding(self, msg, eth_type, src_ip: str, dst_ip: str, ip_pkt):
        dp = msg.datapath
        in_port = msg.match['in_port']

        src_loc = self._get_host_location(src_ip)
        dst_loc = self._get_host_location(dst_ip)
        if not src_loc or not dst_loc:
            return

        src_dpid = src_loc[0]
        dst_dpid, dst_port = dst_loc

        # Extract DSCP from TOS
        dscp_value = (ip_pkt.tos >> 2) & 0x3F

        # Use ECMP to pick a path, using a generic fallback algorithm first
        flow_key = (src_ip, dst_ip, ip_pkt.proto, 0, 0)
        
        # Determine Algorithm via ControlPlaneService (DSCP policy)
        rec_metrics = self.service.evaluate_flow(dscp_value)
        algo = self.service.recommend(rec_metrics).algorithm

        # Downgrade detection: high-security DSCP classes (CS6/CS7/HIGH_SEC/AF11-13)
        # must always use AES-256-GCM. Any other cipher on these classes means an
        # attacker likely manipulated the DSCP field to force a lighter cipher.
        _HIGH_SEC_DSCPS = {48, 56, 63, 10, 12, 14}   # CS6, CS7, HIGH_SEC, AF11-13
        if dscp_value in _HIGH_SEC_DSCPS and algo != "AES-256-GCM":
            PQC_DOWNGRADE_ATTEMPTS.labels(src_ip=src_ip, dst_ip=dst_ip).inc()
            self.logger.warning(
                f"[SECURITY] cipher downgrade on high-sec flow: "
                f"{src_ip}->{dst_ip} DSCP={dscp_value} got cipher={algo}"
            )

        # Select ECMP Path with crypto awareness
        path = self.router.select_path(self.graph, src_dpid, dst_dpid, flow_key, algo)
        if not path:
            return

        # Delegate path activation to the proxy orchestrator
        final_algo = self.service.on_flow_path(path, flow_key, src_ip, dst_ip, dscp_value)

        egress_port = (
            self.graph[path[0]][path[1]]['src_port']
            if len(path) > 1 else dst_port
        )

        self.logger.debug(f"[IP] {src_ip} -> {dst_ip} | DSCP={dscp_value} | ALGO={final_algo} | PATH={path}")

        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=eth_type, ipv4_dst=dst_ip)
        self._install_path(match, path, dst_port, dscp_value)

        out = self._build_packet_out(dp, msg.buffer_id, in_port, egress_port, msg.data)
        dp.send_msg(out)

    def _install_path(self, match, path, final_out_port, dscp_value: int = 0):
        from pqc_sdn.policy.dscp import DscpClass
        latency_sensitive = {DscpClass.EF, DscpClass.CS4,
                             DscpClass.AF41, DscpClass.AF42, DscpClass.AF43}
        queue_id = 0 if DscpClass.from_value(dscp_value) in latency_sensitive else 1

        for i, dpid in reversed(list(enumerate(path))):
            dp = self.dps.get(dpid)
            if not dp:
                continue
            out_port = final_out_port if i == len(path) - 1 else self.graph[dpid][path[i+1]]['src_port']
            # Only use QoS queue on inter-switch (interior) ports — host-facing ports
            # may not have QoS configured and will return an OFP error if queued.
            use_queue = out_port in self.interior_ports.get(dpid, set())
            actions = []
            if use_queue:
                actions.append(dp.ofproto_parser.OFPActionSetQueue(queue_id))
            actions.append(dp.ofproto_parser.OFPActionOutput(out_port))
            self._add_flow(dp, 100, match, actions, idle_timeout=10)

    # =========================================================================
    # PORT STATS POLLING -> ECMP
    # =========================================================================

    def _port_stats_loop(self):
        import psutil
        _proc = psutil.Process()
        while True:
            hub.sleep(2)
            PQC_CONTROLLER_CPU_PERCENT.set(_proc.cpu_percent(interval=None))
            PQC_CONTROLLER_MEMORY_BYTES.set(_proc.memory_info().rss)
            for dp in self.dps.values():
                req = dp.ofproto_parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)
                dp.send_msg(req)

    # SIN 1 FIXED: Implemented actual delta-byte polling for true ECMP load balancing
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        now = time.time()
        
        for stat in body:
            port_no = stat.port_no
            if port_no == ofproto_v1_3.OFPP_LOCAL:
                continue
                
            key = (dpid, port_no)
            tx_bytes = stat.tx_bytes
            
            if key in self._port_stats_prev:
                prev_tx, prev_time = self._port_stats_prev[key]
                dt = now - prev_time
                if dt > 0:
                    delta_tx = tx_bytes - prev_tx
                    throughput_bps = (delta_tx * 8) / dt
                    util = throughput_bps / self.link_capacity

                    THROUGHPUT_BPS.labels(dpid=str(dpid), port_no=str(port_no), direction="tx").set(throughput_bps)
                    LINK_UTILIZATION.labels(dpid=str(dpid), port_no=str(port_no)).set(min(util, 1.0))
                    # PQC overhead: each encrypted frame adds 12-byte nonce + 16-byte auth tag
                    # + 14-byte proxy preamble = 42 bytes on a ~64-byte average OpenFlow message.
                    # overhead_bps ≈ throughput_bps × (42 / 64) ≈ throughput_bps × 0.656
                    PQC_OVERHEAD_BYTES.labels(dpid=str(dpid), port_no=str(port_no)).set(throughput_bps * (42 / 64))

                    # Apply this utilization to any directed link leaving this port
                    for (src, dst), (src_p, dst_p) in self.link_to_port.items():
                        if src == dpid and src_p == port_no:
                            self.router.update_link_utilisation(src, dst, util)
                            break
                            
            self._port_stats_prev[key] = (tx_bytes, now)
