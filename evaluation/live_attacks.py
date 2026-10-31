"""Live adversarial evaluation of the proxy pair.

Runs the real ``sw_proxy_async`` and ``ctrl_proxy`` connection handlers on
loopback with an attacker-controlled relay (Dolev-Yao position) between them:

    fake OVS ──▶ sw_proxy_async ──▶ MITM relay ──▶ ctrl_proxy ──▶ fake Ryu

Each scenario drives legitimate OpenFlow traffic from the fake switch, lets
the relay mount one attack, and records what reached the fake controller:

    delivered_malicious  attacker-chosen bytes reached the endpoint
    plaintext_exposed    a plaintext marker appeared in captured wire bytes
    legit_ok             legitimate traffic still arrived (before the attack)
    closed               the proxy tore the connection down

Usage:
    PYTHONPATH=src python3 evaluation/live_attacks.py [--trials N] [--out PATH]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Awaitable, Callable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pqc_sdn import settings as _settings_mod                      # noqa: E402
from pqc_sdn.crypto.kem import Kem, parse_kem_variant              # noqa: E402
from pqc_sdn.crypto.signatures import SignatureScheme              # noqa: E402
from pqc_sdn.tls.frames import (                                   # noqa: E402
    CIPHER_ID_TO_NAME, CIPHER_NAME_TO_ID, decode_frame, encode_frame, packet_from_frame,
)
from pqc_sdn.tls.handshake import HybridHandshake                  # noqa: E402
from pqc_sdn.tls.messages import (                                 # noqa: E402
    Certificate, ClientHello, EncapsulatedKey, ServerHello,
)
from pqc_sdn.tls.session import MultiCipherSession                 # noqa: E402

LEGIT_MARK = b"LEGIT-OPENFLOW-PAYLOAD"
EVIL_MARK = b"EVIL-INJECTED-FLOWMOD"
_WIRE_HDR = 22


# ── OpenFlow message builders ────────────────────────────────────────────────

def of_msg(of_type: int, body: bytes, xid: int = 1) -> bytes:
    return struct.pack("!BBHI", 4, of_type, 8 + len(body), xid) + body


def packet_in(dscp: int, payload: bytes, sport: int = 5000, dport: int = 6000,
              src=(10, 0, 0, 1), dst=(10, 0, 0, 2)) -> bytes:
    """OF1.3 PACKET_IN carrying Ethernet/IPv4/UDP with the given DSCP."""
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4B4B", 0x45, dscp << 2, 20 + len(udp), 0, 0, 64, 17, 0,
                     *src, *dst) + udp
    eth = b"\x00\x00\x00\x00\x00\x02" + b"\x00\x00\x00\x00\x00\x01" + b"\x08\x00" + ip
    match = struct.pack("!HH", 1, 12) + struct.pack("!HBBI", 0x8000, 0, 4, 1) + b"\x00" * 4
    body = struct.pack("!IHBBQ", 0xFFFFFFFF, len(eth), 0, 0, 0) + match + b"\x00\x00" + eth
    return of_msg(10, body)


def echo_request(payload: bytes, xid: int = 1) -> bytes:
    return of_msg(2, payload, xid)


# ── Test stack ───────────────────────────────────────────────────────────────

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Endpoint:
    """Fake Ryu: records every byte it receives."""
    received: bytearray = field(default_factory=bytearray)
    connections: int = 0
    writers: list = field(default_factory=list)

    async def handle(self, reader, writer):
        self.connections += 1
        self.writers.append(writer)
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                self.received.extend(chunk)
        finally:
            writer.close()


class Relay:
    """Attacker relay between sw_proxy and ctrl_proxy.

    Parses the PQC\\x02 handshake (8-byte preamble, one length-prefixed
    message up, three down) and then tunnel wire frames, exposing hooks:

        up_handshake(msg) -> msg            ClientHello bytes
        down_handshake([m2, m3, m4]) -> [...]
        up_frame(frame, idx) -> [frames]    switch→controller wire frames
    """

    def __init__(self, target_port: int) -> None:
        self.target_port = target_port
        self.captured_up = bytearray()
        self.captured_down = bytearray()
        self.up_frames: List[bytes] = []
        self.down_frames: List[bytes] = []
        self.up_handshake: Callable[[bytes], bytes] = lambda m: m
        self.down_handshake: Callable[[list], list] = lambda ms: ms
        self.up_frame: Callable[[bytes, int], list] = lambda f, i: [f]
        self.extra_up: Optional[Callable[[asyncio.StreamWriter], Awaitable[None]]] = None
        self.ctrl_writer: Optional[asyncio.StreamWriter] = None
        self.closed_by_peer = asyncio.Event()

    @staticmethod
    async def _read_lp(reader) -> bytes:
        hdr = await reader.readexactly(4)
        return hdr + await reader.readexactly(struct.unpack("!I", hdr)[0])

    async def handle(self, sw_reader, sw_writer):
        ctrl_reader, ctrl_writer = await asyncio.open_connection("127.0.0.1", self.target_port)
        self.ctrl_writer = ctrl_writer
        try:
            preamble = await sw_reader.readexactly(8)
            hello = (await self._read_lp(sw_reader))[4:]
            hello = self.up_handshake(hello)
            ctrl_writer.write(preamble + struct.pack("!I", len(hello)) + hello)
            await ctrl_writer.drain()
            msgs = [(await self._read_lp(ctrl_reader))[4:] for _ in range(3)]
            msgs = self.down_handshake(msgs)
            for m in msgs:
                sw_writer.write(struct.pack("!I", len(m)) + m)
            await sw_writer.drain()
            await asyncio.gather(
                self._pipe(sw_reader, ctrl_writer, up=True),
                self._pipe(ctrl_reader, sw_writer, up=False),
            )
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self.closed_by_peer.set()
            for w in (sw_writer, ctrl_writer):
                w.close()

    async def _pipe(self, reader, writer, up: bool):
        buf = b""
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            (self.captured_up if up else self.captured_down).extend(chunk)
            buf += chunk
            while len(buf) >= 4:
                n = struct.unpack_from("!I", buf)[0]
                if len(buf) < n:
                    break
                frame, buf = buf[:n], buf[n:]
                if up:
                    idx = len(self.up_frames)
                    self.up_frames.append(frame)
                    out = self.up_frame(frame, idx)
                else:
                    self.down_frames.append(frame)
                    out = [frame]
                for f in out:
                    writer.write(f)
                await writer.drain()
        writer.close()


class Stack:
    """fake OVS → sw_proxy → Relay → ctrl_proxy → fake Ryu, all on loopback."""

    def __init__(self, pinned: bool = True, legacy: bool = False, mutual: bool = True) -> None:
        self.pinned = pinned
        self.legacy = legacy
        self.mutual = mutual

    async def __aenter__(self):
        from pqc_sdn.apps import ctrl_proxy, sw_proxy_async
        self.ryu_port, self.ctrl_port, self.relay_port, self.sw_port = (
            _free_port() for _ in range(4))
        base = _settings_mod.get_settings()
        # Private switch identity + allowlist for this stack.
        import tempfile
        ident_dir = Path(tempfile.mkdtemp(prefix="la_ident_"))
        proxy = replace(
            base.proxy,
            controller_host="127.0.0.1", controller_port=self.relay_port,
            ctrl_proxy_port=self.ctrl_port, ryu_port=self.ryu_port,
            base_data_port=self.sw_port,
            require_pinning=self.pinned,
            allow_legacy_plan_mode=self.legacy,
            pinned_identity_key="",
            mutual_auth=self.mutual,
            switch_identity_public_key_file=str(ident_dir / "sw.pk"),
            switch_identity_secret_key_file=str(ident_dir / "sw.sk"),
            authorized_switch_keys_file=str(ident_dir / "authorized.txt"),
            identity_public_key_file=(base.proxy.identity_public_key_file if self.pinned
                                      else "certs/__no_pin__.pk"),
        )
        self._saved = _settings_mod._settings
        _settings_mod._settings = replace(base, proxy=proxy)
        from pqc_sdn.tls.identity import authorize_switch_key, load_or_create_switch_identity
        authorize_switch_key(load_or_create_switch_identity().public_key)
        # Private override file so a stale run/cipher_override cannot skew results.
        import tempfile
        from pqc_sdn.policy import engine as _eng
        self._override_env = os.environ.get("PQC_OVERRIDE_FILE")
        os.environ["PQC_OVERRIDE_FILE"] = os.path.join(tempfile.mkdtemp(), "cipher_override")
        _eng._override_cache = (-1.0, None)
        self._env = os.environ.get("PQC_ALLOW_UNPINNED")
        if not self.pinned:
            os.environ["PQC_ALLOW_UNPINNED"] = "1"

        self.ryu = Endpoint()
        self.relay = Relay(self.ctrl_port)
        self._servers = [
            await asyncio.start_server(self.ryu.handle, "127.0.0.1", self.ryu_port),
            await asyncio.start_server(ctrl_proxy.handle_connection, "127.0.0.1", self.ctrl_port),
            await asyncio.start_server(self.relay.handle, "127.0.0.1", self.relay_port),
            await asyncio.start_server(sw_proxy_async.handle_switch_connection,
                                       "127.0.0.1", self.sw_port),
        ]
        return self

    async def __aexit__(self, *exc):
        for s in self._servers:
            s.close()
        _settings_mod._settings = self._saved
        if self._override_env is None:
            os.environ.pop("PQC_OVERRIDE_FILE", None)
        else:
            os.environ["PQC_OVERRIDE_FILE"] = self._override_env
        if self._env is None:
            os.environ.pop("PQC_ALLOW_UNPINNED", None)
        else:
            os.environ["PQC_ALLOW_UNPINNED"] = self._env

    async def switch(self):
        return await asyncio.open_connection("127.0.0.1", self.sw_port)


async def _settle(cond: Callable[[], bool], timeout: float = 3.0) -> bool:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if cond():
            return True
        await asyncio.sleep(0.01)
    return cond()


async def _send_legit(ovs_w, ryu: Endpoint, n: int = 3) -> bool:
    for i in range(n):
        ovs_w.write(echo_request(LEGIT_MARK + b"-%d" % i, xid=100 + i))
    await ovs_w.drain()
    return await _settle(lambda: ryu.received.count(LEGIT_MARK) >= n)


# ── Scenarios ────────────────────────────────────────────────────────────────

@dataclass
class Result:
    scenario: str
    defense: str
    delivered_malicious: bool = False
    plaintext_exposed: bool = False
    legit_ok: bool = False
    closed: bool = False
    note: str = ""

    @property
    def defended(self) -> bool:
        return not self.delivered_malicious and not self.plaintext_exposed


def _flip(frame: bytes, offset: int) -> bytes:
    b = bytearray(frame)
    b[offset] ^= 0x01
    return bytes(b)


async def _frame_attack(name: str, defense: str, mutate, after: int = 3) -> Result:
    """Generic tunnel-frame attack: once `after` legit frames have passed,
    the relay rewrites the next frame with `mutate(frame, history)`."""
    async with Stack() as st:
        relay = st.relay

        def hook(frame, idx):
            if idx == after:
                return mutate(frame, relay.up_frames)
            return [frame]
        relay.up_frame = hook

        r, w = await st.switch()
        res = Result(name, defense)
        res.legit_ok = await _send_legit(w, st.ryu, after)
        before = len(st.ryu.received)
        w.write(echo_request(EVIL_MARK, xid=999))
        await w.drain()
        res.closed = await _settle(lambda: relay.closed_by_peer.is_set(), 2.0)
        res.delivered_malicious = EVIL_MARK in st.ryu.received[before:] and name != "frame_drop"
        if name == "replay":
            # replayed frame carries a LEGIT payload: success = it arrived twice
            res.delivered_malicious = st.ryu.received.count(LEGIT_MARK) > after
        if name == "reorder":
            res.delivered_malicious = st.ryu.received.count(LEGIT_MARK) > after
        w.close()
        return res


async def scenario_passive_capture() -> Result:
    async with Stack() as st:
        r, w = await st.switch()
        res = Result("passive_capture_hndl", "ML-KEM + AEAD")
        res.legit_ok = await _send_legit(w, st.ryu)
        res.plaintext_exposed = LEGIT_MARK in st.relay.captured_up
        w.close()
        return res


async def scenario_injection_raw() -> Result:
    """Inject a plaintext FLOW_MOD after a length field the proxy cannot parse
    (the pre-fix passthrough path)."""
    async with Stack() as st:
        r, w = await st.switch()
        res = Result("inject_unparseable_length", "fail-closed framing")
        res.legit_ok = await _send_legit(w, st.ryu)
        before = len(st.ryu.received)
        st.relay.ctrl_writer.write(struct.pack("!I", 0xFFFFFFF0) + of_msg(14, EVIL_MARK))
        await st.relay.ctrl_writer.drain()
        res.closed = await _settle(lambda: st.relay.closed_by_peer.is_set(), 2.0)
        res.delivered_malicious = EVIL_MARK in st.ryu.received[before:]
        w.close()
        return res


async def scenario_injection_forged() -> Result:
    async with Stack() as st:
        r, w = await st.switch()
        res = Result("inject_forged_frame", "AEAD tag")
        res.legit_ok = await _send_legit(w, st.ryu)
        before = len(st.ryu.received)
        body = os.urandom(272)
        forged = struct.pack("!IIBB", _WIRE_HDR + len(body), 50, 0, 0) + os.urandom(12) + body
        st.relay.ctrl_writer.write(forged)
        await st.relay.ctrl_writer.drain()
        res.closed = await _settle(lambda: st.relay.closed_by_peer.is_set(), 2.0)
        res.delivered_malicious = len(st.ryu.received) > before
        w.close()
        return res


async def scenario_legacy_downgrade() -> Result:
    """Attacker opens a PQC\\x00 (legacy plan-poll) connection to ctrl_proxy and
    sends plaintext OpenFlow."""
    async with Stack() as st:
        res = Result("legacy_mode_downgrade", "legacy mode disabled")
        r, w = await asyncio.open_connection("127.0.0.1", st.ctrl_port)
        w.write(b"PQC\x00" + struct.pack("!I", 7) + of_msg(14, EVIL_MARK))
        await w.drain()
        await asyncio.sleep(0.5)
        res.delivered_malicious = EVIL_MARK in st.ryu.received
        res.closed = r.at_eof() or (await r.read(1)) == b""
        res.legit_ok = True
        w.close()
        return res


async def scenario_kem_substitution() -> Result:
    """Attacker encapsulates to the switch's pk_e and substitutes c'."""
    async with Stack() as st:
        res = Result("mitm_kem_ct_substitution", "transcript-bound ML-DSA-87 signature")
        state = {}

        def up(msg):
            state["hello"] = ClientHello.deserialize(msg)
            return msg

        def down(msgs):
            hello = state["hello"]
            enc = Kem(parse_kem_variant(hello.ml_kem_variant)).encapsulate(hello.kem_public_key)
            encap = EncapsulatedKey.deserialize(msgs[2])
            encap.ciphertext = enc.ciphertext
            return [msgs[0], msgs[1], encap.serialize()]

        st.relay.up_handshake, st.relay.down_handshake = up, down
        r, w = await st.switch()
        res.legit_ok = not await _send_legit(w, st.ryu, 1)   # expected to fail
        res.delivered_malicious = LEGIT_MARK in st.ryu.received
        res.closed = await _settle(lambda: st.relay.closed_by_peer.is_set(), 2.0)
        res.note = "handshake aborted" if not res.delivered_malicious else "handshake accepted"
        w.close()
        return res


async def scenario_impersonation(pinned: bool) -> Result:
    """Full MITM: attacker answers the switch with its own ML-DSA-87 identity
    and runs a separate, honest handshake with ctrl_proxy, then decrypts and
    re-encrypts every frame (plaintext read and injection)."""
    name = "mitm_impersonation_" + ("pinned" if pinned else "unpinned")
    res = Result(name, "certificate pinning" if pinned else "none (pinning disabled)")
    async with Stack(pinned=pinned) as st:
        relay = st.relay
        attacker_id = SignatureScheme().keygen()
        recovered = bytearray()

        async def handle(sw_reader, sw_writer):
            ctrl_reader, ctrl_writer = await asyncio.open_connection("127.0.0.1", st.ctrl_port)
            relay.ctrl_writer = ctrl_writer
            try:
                preamble = await sw_reader.readexactly(8)
                hello_raw = (await Relay._read_lp(sw_reader))[4:]
                hello = ClientHello.deserialize(hello_raw)
                # Leg 1: impersonate the controller towards the switch.
                fake_srv = HybridHandshake("attacker", identity=attacker_id)
                sh, cert, enc, bound = fake_srv.server_respond(hello)
                for m in (sh, cert, enc):
                    b = m.serialize()
                    sw_writer.write(struct.pack("!I", len(b)) + b)
                await sw_writer.drain()
                from pqc_sdn.tls.session import derive_directional_keys
                s_send, s_recv = derive_directional_keys(bound, sh.session_id)
                leg1 = MultiCipherSession(sh.session_id, s_recv, s_send, "k1", "atk", "sw")
                # Leg 2: honest client towards ctrl_proxy (no pin needed by attacker).
                fake_cli = HybridHandshake("attacker-cli")
                h2 = fake_cli.create_client_hello(parse_kem_variant(hello.ml_kem_variant))
                b = h2.serialize()
                ctrl_writer.write(preamble + struct.pack("!I", len(b)) + b)
                await ctrl_writer.drain()
                m2, m3, m4 = [(await Relay._read_lp(ctrl_reader))[4:] for _ in range(3)]
                r2 = fake_cli.client_complete(ServerHello.deserialize(m2),
                                              Certificate.deserialize(m3),
                                              EncapsulatedKey.deserialize(m4))
                leg2 = MultiCipherSession(r2.session_id, r2.session.send_key,
                                          r2.session.recv_key, "k2", "atk", "ctrl")
                buf = b""
                while True:
                    chunk = await sw_reader.read(65536)
                    if not chunk:
                        break
                    buf += chunk
                    while len(buf) >= 4 and len(buf) >= struct.unpack_from("!I", buf)[0]:
                        n = struct.unpack_from("!I", buf)[0]
                        frame, buf = buf[:n], buf[n:]
                        wf = decode_frame(frame)
                        name_ = CIPHER_ID_TO_NAME[wf.cipher_id]
                        plain = leg1.decrypt(packet_from_frame(wf, "k1"), cipher_name=name_)
                        recovered.extend(plain)
                        plain = plain.replace(LEGIT_MARK, EVIL_MARK)   # tamper in flight
                        pkt = leg2.encrypt(plain, cipher_name=name_)
                        ctrl_writer.write(encode_frame(pkt, cipher_id=wf.cipher_id))
                        await ctrl_writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, Exception):
                pass
            finally:
                relay.closed_by_peer.set()
                sw_writer.close()
                ctrl_writer.close()

        st._servers[2].close()
        st._servers[2] = await asyncio.start_server(handle, "127.0.0.1", st.relay_port)
        r, w = await st.switch()
        for i in range(3):
            w.write(echo_request(LEGIT_MARK + b"-%d" % i))
        await w.drain()
        await _settle(lambda: EVIL_MARK in st.ryu.received, 2.0)
        res.plaintext_exposed = LEGIT_MARK in recovered
        res.delivered_malicious = EVIL_MARK in st.ryu.received
        res.note = (f"plaintext_exposed={res.plaintext_exposed} "
                    f"tampered_reached_ctrl={res.delivered_malicious}")
        res.closed = relay.closed_by_peer.is_set()
        res.legit_ok = True
        w.close()
    return res


async def scenario_dscp_downgrade() -> Result:
    """Remark a flow from AF11 (AES-256-GCM) to BE (AES-128-GCM) mid-flow and
    check, on the wire, which cipher protected the remarked packets."""
    from pqc_sdn.policy import engine as eng
    async with Stack() as st:
        res = Result("dscp_remark_downgrade", "per-flow DSCP baseline")
        r, w = await st.switch()
        before = eng._FRAME_ENGINE.downgrade_events if eng._FRAME_ENGINE else 0
        sport = 40000 + os.getpid() % 10000
        w.write(packet_in(10, LEGIT_MARK, sport=sport))           # AF11 first
        for _ in range(3):
            w.write(packet_in(0, LEGIT_MARK, sport=sport))        # remarked to BE
        await w.drain()
        await _settle(lambda: len(st.relay.up_frames) >= 4)
        ids = [f[9] for f in st.relay.up_frames[:4]]
        after = eng._FRAME_ENGINE.downgrade_events if eng._FRAME_ENGINE else 0
        res.delivered_malicious = any(i != CIPHER_NAME_TO_ID["AES-256-GCM"] for i in ids)
        res.legit_ok = await _settle(lambda: st.ryu.received.count(LEGIT_MARK) >= 4)
        res.note = f"wire cipher_ids={ids} downgrade_events+={after - before}"
        w.close()
        return res


async def scenario_rogue_switch(mode: str) -> Result:
    """A rogue switch proxy connects straight to ctrl_proxy and completes a
    valid PQ handshake, then tries to deliver OpenFlow to the controller.

    mode: "unauthorized_key" — sends a correctly signed ClientAuth with its
          own (non-allowlisted) ML-DSA-87 key;
          "no_auth"          — skips ClientAuth and sends OpenFlow directly;
          "mutual_off"       — negative control: mutual auth disabled.
    """
    defense = {"unauthorized_key": "switch allowlist (mutual auth)",
               "no_auth": "mandatory ClientAuth (mutual auth)",
               "mutual_off": "none (mutual auth disabled)"}[mode]
    res = Result(f"rogue_switch_{mode}", defense)
    async with Stack(mutual=(mode != "mutual_off")) as st:
        from pqc_sdn.tls.messages import ClientAuth
        from pqc_sdn.tls.session import derive_directional_keys  # noqa: F401
        r, w = await asyncio.open_connection("127.0.0.1", st.ctrl_port)
        hs = HybridHandshake("rogue-switch")
        hello = hs.create_client_hello(parse_kem_variant(
            _settings_mod.get_settings().crypto.control_plane_kem))
        b = hello.serialize()
        w.write(b"PQC\x02" + struct.pack("!I", 4242) + struct.pack("!I", len(b)) + b)
        await w.drain()
        m2, m3, m4 = [(await Relay._read_lp(r))[4:] for _ in range(3)]
        out = hs.client_complete(ServerHello.deserialize(m2), Certificate.deserialize(m3),
                                 EncapsulatedKey.deserialize(m4))
        sess = MultiCipherSession(out.session_id, out.session.send_key, out.session.recv_key,
                                  "k", "rogue", "ctrl")
        if mode == "unauthorized_key":
            auth = hs.create_client_auth(SignatureScheme().keygen())
            pkt = sess.encrypt(ClientAuth.MAGIC + auth.serialize(), cipher_name="AES-256-GCM")
            w.write(encode_frame(pkt, cipher_id=CIPHER_NAME_TO_ID["AES-256-GCM"]))
        pkt = sess.encrypt(of_msg(14, EVIL_MARK), cipher_name="AES-256-GCM")
        w.write(encode_frame(pkt, cipher_id=CIPHER_NAME_TO_ID["AES-256-GCM"]))
        await w.drain()
        await _settle(lambda: EVIL_MARK in st.ryu.received, 1.5)
        res.delivered_malicious = EVIL_MARK in st.ryu.received
        try:
            res.closed = (await asyncio.wait_for(r.read(1), 1.0)) == b""
        except asyncio.TimeoutError:
            res.closed = False
        res.legit_ok = True
        w.close()
    return res


def _replay_mutation(frame, history):
    return [frame, history[0]]


def _reorder_mutation(frame, history):
    return [frame, history[-2]] if len(history) >= 2 else [frame]


SCENARIOS = [
    ("passive_capture_hndl", scenario_passive_capture),
    ("inject_unparseable_length", scenario_injection_raw),
    ("inject_forged_frame", scenario_injection_forged),
    ("ciphertext_bitflip", lambda: _frame_attack(
        "ciphertext_bitflip", "AEAD tag", lambda f, h: [_flip(f, _WIRE_HDR + 5)])),
    ("header_seq_tamper", lambda: _frame_attack(
        "header_seq_tamper", "seq/epoch in AAD", lambda f, h: [_flip(f, 7)])),
    ("cipher_id_rewrite", lambda: _frame_attack(
        "cipher_id_rewrite", "per-cipher keys",
        lambda f, h: [f[:9] + bytes([(f[9] + 1) % 3]) + f[10:]])),
    ("replay", lambda: _frame_attack("replay", "monotonic sequence", _replay_mutation)),
    ("reorder", lambda: _frame_attack("reorder", "monotonic sequence", _reorder_mutation)),
    ("legacy_mode_downgrade", scenario_legacy_downgrade),
    ("mitm_kem_ct_substitution", scenario_kem_substitution),
    ("mitm_impersonation_pinned", lambda: scenario_impersonation(True)),
    ("mitm_impersonation_unpinned", lambda: scenario_impersonation(False)),
    ("dscp_remark_downgrade", scenario_dscp_downgrade),
    ("rogue_switch_unauthorized_key", lambda: scenario_rogue_switch("unauthorized_key")),
    ("rogue_switch_no_auth", lambda: scenario_rogue_switch("no_auth")),
    ("rogue_switch_mutual_off", lambda: scenario_rogue_switch("mutual_off")),
]


async def run_all(trials: int = 1, only: Optional[List[str]] = None) -> List[dict]:
    rows = []
    for name, fn in SCENARIOS:
        if only and name not in only:
            continue
        outcomes = []
        for _ in range(trials):
            outcomes.append(await fn())
        first = outcomes[0]
        rows.append({
            "scenario": name,
            "defense": first.defense,
            "trials": trials,
            "attack_success": sum(not o.defended for o in outcomes),
            "legit_ok": sum(o.legit_ok for o in outcomes),
            "conn_closed": sum(o.closed for o in outcomes),
            "note": first.note,
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--only", default="")
    ap.add_argument("--out", default=str(ROOT / "evaluation/results/raw/live_attacks.json"))
    args = ap.parse_args()
    import logging
    logging.disable(logging.WARNING)
    rows = asyncio.run(run_all(args.trials, [s for s in args.only.split(",") if s] or None))
    print(f"{'scenario':32s} {'defense':38s} {'success':>8s} {'closed':>7s}  note")
    for r in rows:
        print(f"{r['scenario']:32s} {r['defense']:38s} "
              f"{r['attack_success']:>3d}/{r['trials']:<4d} {r['conn_closed']:>3d}/{r['trials']:<3d} {r['note']}")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(rows, indent=1))
    print(f"\n→ {args.out}")


if __name__ == "__main__":
    main()
