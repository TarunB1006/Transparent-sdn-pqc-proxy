"""
sw_proxy_async.py — Single-process asyncio multiplexing proxy for all OVS switches.

Replaces the per-switch subprocess.Popen loop in run_mininet.py.
One Python process, one listening port, N concurrent switch connections.

Architecture
------------
  OVS switch N → TCP :6634 → sw_proxy_async (one coroutine per switch)
                              ↓  ML-KEM handshake over TCP (real cross-process key exchange)
                              ↓  AEAD tunnel (per-frame AES-256-GCM / AES-128-GCM / ChaCha20-Poly1305)
                              → ctrl_proxy :6652

Handshake protocol (PQC\\x02 magic)
------------------------------------
When a new OVS switch connects, sw_proxy_async immediately opens a TCP connection
to ctrl_proxy and performs the switch side of the ML-KEM handshake:
  1. Send preamble: PQC\\x02 + conn_id (4 bytes, random)
  2. Send length-prefixed ClientHello (ML-KEM public key + identity)
  3. Receive length-prefixed ServerHello, Certificate, EncapsulatedKey
  4. Call client_complete() → decapsulate shared secret → derive send/recv keys
Data then flows immediately with encryption active — no plan-API polling required.

CPU-bound offload
-----------------
liboqs ML-KEM encapsulation is a blocking C call.  All crypto calls are
wrapped with loop.run_in_executor(executor, ...) so they never stall the
event loop.  Default pool: ThreadPoolExecutor(min(32, cpu_count+4)).

Usage
-----
    python -m pqc_sdn.apps.sw_proxy_async
    # Or via run_mininet.py which launches this once before starting Mininet.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time as _time
from concurrent.futures import ThreadPoolExecutor

from pqc_sdn.exceptions import FrameError, HandshakeError
from pqc_sdn.logging_config import configure_logging, get_logger
from pqc_sdn.settings import get_settings
from pqc_sdn.tls.frames import (
    decode_frame, encode_frame, packet_from_frame,
    CIPHER_ID_TO_NAME, CIPHER_NAME_TO_ID,
)
from pqc_sdn.policy.engine import select_frame_cipher as _select_cipher
from pqc_sdn.tls.session import SecureSession, MultiCipherSession


# ── Control-plane message timing collector ────────────────────────
# Lightweight, lock-free accumulator for per-OF-message encrypt/decrypt times.
# Written by the hot path; read by the metrics exporter or evaluation harness.
class _CpMetrics:
    __slots__ = ("encrypt_ns", "decrypt_ns", "encrypt_count", "decrypt_count",
                 "msg_sizes", "enabled")

    def __init__(self):
        self.encrypt_ns: list[int] = []
        self.decrypt_ns: list[int] = []
        self.encrypt_count = 0
        self.decrypt_count = 0
        self.msg_sizes: list[int] = []
        self.enabled = os.environ.get("PQC_CP_METRICS", "0") == "1"

    def record_encrypt(self, ns: int, msg_size: int):
        if not self.enabled:
            return
        self.encrypt_ns.append(ns)
        self.msg_sizes.append(msg_size)
        self.encrypt_count += 1

    def record_decrypt(self, ns: int):
        if not self.enabled:
            return
        self.decrypt_ns.append(ns)
        self.decrypt_count += 1

    def snapshot(self) -> dict:
        import numpy as np
        result = {"encrypt_count": self.encrypt_count, "decrypt_count": self.decrypt_count}
        if self.encrypt_ns:
            arr = np.array(self.encrypt_ns) / 1000  # ns → µs
            result["encrypt_mean_us"] = round(float(np.mean(arr)), 2)
            result["encrypt_p50_us"] = round(float(np.median(arr)), 2)
            result["encrypt_p99_us"] = round(float(np.percentile(arr, 99)), 2)
        if self.decrypt_ns:
            arr = np.array(self.decrypt_ns) / 1000
            result["decrypt_mean_us"] = round(float(np.mean(arr)), 2)
            result["decrypt_p50_us"] = round(float(np.median(arr)), 2)
            result["decrypt_p99_us"] = round(float(np.percentile(arr, 99)), 2)
        if self.msg_sizes:
            result["msg_size_mean"] = round(float(np.mean(self.msg_sizes)), 1)
        return result

    def reset(self):
        self.encrypt_ns.clear()
        self.decrypt_ns.clear()
        self.msg_sizes.clear()
        self.encrypt_count = 0
        self.decrypt_count = 0


CP_METRICS = _CpMetrics()

log = get_logger("pqc.sw_proxy_async")

_POOL_SIZE = min(32, (os.cpu_count() or 4) + 4)
_executor = ThreadPoolExecutor(max_workers=_POOL_SIZE, thread_name_prefix="pqc-crypto")

_HANDSHAKE_MAGIC = b"PQC\x02"   # handshake-first protocol: KEM exchange before data
_WIRE_HDR_LEN = 22              # v2: total_len(4)+seq(4)+epoch(1)+cipher_id(1)+nonce(12)
_OF_HDR_LEN = 8


# ---------------------------------------------------------------------------
# Handshake helpers
# ---------------------------------------------------------------------------

async def _read_msg(reader: asyncio.StreamReader, timeout: float = 10.0) -> bytes:
    """Read one length-prefixed message (4-byte big-endian length + payload)."""
    hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    msg_len = struct.unpack("!I", hdr)[0]
    if msg_len == 0 or msg_len > 1_048_576:
        raise ValueError(f"invalid handshake message length: {msg_len}")
    return await asyncio.wait_for(reader.readexactly(msg_len), timeout=timeout)


async def _sw_pqc_handshake(
    ctrl_reader: asyncio.StreamReader,
    ctrl_writer: asyncio.StreamWriter,
    conn_id: int,
    loop,
) -> tuple[SecureSession, SecureSession]:
    """Switch-side ML-KEM handshake with ctrl_proxy over a real TCP connection.

    Sends ClientHello, receives ServerHello + Certificate + EncapsulatedKey,
    decapsulates the shared secret, and derives independent send/recv keys.
    Returns (send_session, recv_session) ready for immediate frame encryption.
    """
    from pqc_sdn.tls.handshake import HybridHandshake
    from pqc_sdn.tls.messages import ServerHello, Certificate, EncapsulatedKey

    sw_hs = HybridHandshake(f"sw-{conn_id}")
    # Read KEM variant from configuration instead of hardcoding
    from pqc_sdn.crypto.kem import parse_kem_variant
    kem_variant = parse_kem_variant(get_settings().crypto.control_plane_kem)
    hello = await loop.run_in_executor(
        _executor, sw_hs.create_client_hello, kem_variant
    )

    blob = hello.serialize()
    ctrl_writer.write(struct.pack("!I", len(blob)) + blob)
    await ctrl_writer.drain()

    sh_raw   = await _read_msg(ctrl_reader)
    cert_raw = await _read_msg(ctrl_reader)
    enc_raw  = await _read_msg(ctrl_reader)

    s_hello = ServerHello.deserialize(sh_raw)
    cert    = Certificate.deserialize(cert_raw)
    encap   = EncapsulatedKey.deserialize(enc_raw)

    # Load pinned identity key for certificate verification (MITM protection).
    # If configured, client_complete will reject any server whose identity
    # public key doesn't match the pinned value.
    # Pinning is mandatory (fail closed). PQC_ALLOW_UNPINNED=1 exists only to
    # reproduce the unpinned-deployment MITM experiment.
    from pqc_sdn.tls.identity import load_pinned_key
    pinned_key = load_pinned_key()
    if pinned_key is None and (
        get_settings().proxy.require_pinning
        and os.environ.get("PQC_ALLOW_UNPINNED") != "1"
    ):
        raise HandshakeError("no pinned controller identity configured; refusing handshake")

    result = await loop.run_in_executor(
        _executor, sw_hs.client_complete, s_hello, cert, encap, pinned_key
    )

    # Use the session keys derived by client_complete() — these are bound to
    # the transcript MAC, matching what ctrl_proxy derives from server_respond().
    # Do NOT re-derive from result.shared_secret (raw KEM output) — that would
    # mismatch because server_respond() returns bound_secret, not raw secret.
    session = result.session
    key_id = session.key_id

    # Create MultiCipherSession for per-frame DSCP-adaptive cipher selection.
    # All three ciphers (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305) share
    # the same key material from the ML-KEM handshake.
    # One session object serves both directions (independent send/recv keys
    # and sequence counters).
    send_sess = recv_sess = MultiCipherSession(
        session.session_id, session.send_key, session.recv_key, key_id,
        f"sw-{conn_id}", "ctrl_proxy",
    )

    # Mutual authentication: the first frame inside the tunnel carries this
    # proxy's ML-DSA-87 identity and a signature over the full transcript.
    if get_settings().proxy.mutual_auth:
        from pqc_sdn.tls.identity import load_or_create_switch_identity
        from pqc_sdn.tls.messages import ClientAuth
        auth = await loop.run_in_executor(
            _executor, sw_hs.create_client_auth, load_or_create_switch_identity()
        )
        pkt = send_sess.encrypt(ClientAuth.MAGIC + auth.serialize(), cipher_name="AES-256-GCM")
        ctrl_writer.write(encode_frame(pkt, cipher_id=CIPHER_NAME_TO_ID["AES-256-GCM"]))
        await ctrl_writer.drain()

    log.info("[SW-PROXY] conn=%d handshake OK variant=%s key=%s",
             conn_id, result.kem_variant, key_id)
    return send_sess, recv_sess


# ---------------------------------------------------------------------------
# Pipe coroutines
# ---------------------------------------------------------------------------

async def _pipe_ovs_to_ctrl(
    ovs_reader: asyncio.StreamReader,
    ctrl_writer: asyncio.StreamWriter,
    state: dict,
) -> None:
    """Read plaintext OpenFlow from OVS switch → encrypt → forward to ctrl_proxy.
    Sniffs Features-Reply to learn the real dpid and extracts DSCP from
    PacketIn inner IP headers for per-frame cipher selection."""
    # Mode B override: if PQC_FIXED_CIPHER is set, bypass DSCP policy engine
    _fixed_cipher = os.environ.get("PQC_FIXED_CIPHER")
    if _fixed_cipher:
        log.info("[SW-PROXY] FIXED CIPHER MODE: %s (DSCP policy bypassed)", _fixed_cipher)
    buf = b""
    bufsz = get_settings().proxy.read_buffer_size
    _dpid_resolved = False

    while True:
        chunk = await ovs_reader.read(bufsz)
        if not chunk:
            break
        buf += chunk

        # Sniff plaintext buffer for Features-Reply to learn real dpid.
        if not _dpid_resolved:
            dpid = _extract_dpid(buf)
            if dpid is not None:
                _dpid_resolved = True
                state["dpid"] = dpid
                log.info("[SW-PROXY] dpid=%d resolved (encryption already active)", dpid)

        while len(buf) >= _OF_HDR_LEN:
            of_len = struct.unpack_from("!H", buf, 2)[0]
            if of_len < 8 or of_len > 65536:
                # Never forward unparseable bytes: close the connection.
                raise FrameError(f"invalid OpenFlow length {of_len} from switch")
            if len(buf) < of_len:
                break
            frame, buf = buf[:of_len], buf[of_len:]

            cipher_name = _fixed_cipher or _select_cipher(frame)
            cipher_id = CIPHER_NAME_TO_ID[cipher_name]

            _t0 = _time.perf_counter_ns()
            pkt = state["send"].encrypt(frame, cipher_name=cipher_name)
            _enc_ns = _time.perf_counter_ns() - _t0
            CP_METRICS.record_encrypt(_enc_ns, len(frame))
            ctrl_writer.write(encode_frame(pkt, cipher_id=cipher_id))
            await ctrl_writer.drain()


async def _pipe_ctrl_to_ovs(
    ctrl_reader: asyncio.StreamReader,
    ovs_writer: asyncio.StreamWriter,
    state: dict,
) -> None:
    """Read encrypted wire frames from ctrl_proxy → decrypt → forward to OVS switch.
    Uses cipher_id from wire header to select the correct decryption cipher."""
    buf = b""
    bufsz = get_settings().proxy.read_buffer_size
    while True:
        chunk = await ctrl_reader.read(bufsz)
        if not chunk:
            break
        buf += chunk

        while len(buf) >= _WIRE_HDR_LEN:
            total_len = struct.unpack_from("!I", buf, 0)[0]
            if total_len < _WIRE_HDR_LEN or total_len > 131072:
                # Never forward unauthenticated bytes to the switch.
                raise FrameError(f"invalid wire frame length {total_len}")
            if len(buf) < total_len:
                break
            frame_data, buf = buf[:total_len], buf[total_len:]
            try:
                wf = decode_frame(frame_data)
                cipher_name = CIPHER_ID_TO_NAME.get(wf.cipher_id)
                if cipher_name is None:
                    raise FrameError(f"unknown cipher_id {wf.cipher_id}")
                pkt = packet_from_frame(wf, state["recv"].key_id)
                _t0 = _time.perf_counter_ns()
                plain = state["recv"].decrypt(pkt, cipher_name=cipher_name)
                _dec_ns = _time.perf_counter_ns() - _t0
            except Exception as exc:
                # Authentication/replay failure is fatal, as in TLS.
                log.error("[SW-PROXY] dpid=%d rejecting frame and closing: %s",
                          state["dpid"], exc)
                raise FrameError(str(exc)) from exc
            CP_METRICS.record_decrypt(_dec_ns)
            ovs_writer.write(plain)
            await ovs_writer.drain()


# ---------------------------------------------------------------------------
# Per-switch connection handler
# ---------------------------------------------------------------------------

def _extract_dpid(data: bytes) -> int | None:
    """
    Scan a byte buffer for an OpenFlow Features-Reply (type=6) and extract
    the 64-bit datapath_id.

    OF1.3 Features-Reply layout (bytes):
      0: version, 1: type=6, 2-3: length, 4-7: xid, 8-15: datapath_id
    """
    i = 0
    while i + 16 <= len(data):
        if data[i + 1] == 6:          # OF type = OFPT_FEATURES_REPLY
            dpid = struct.unpack_from("!Q", data, i + 8)[0]
            return dpid
        # Advance by the frame length field to skip to next OF message
        frame_len = struct.unpack_from("!H", data, i + 2)[0]
        if frame_len < 8:
            break
        i += frame_len
    return None

async def handle_switch_connection(
    ovs_reader: asyncio.StreamReader,
    ovs_writer: asyncio.StreamWriter,
) -> None:
    settings = get_settings()
    peer = ovs_writer.get_extra_info("peername", ("?", 0))
    log.info("[SW-PROXY] new connection from %s:%s", peer[0], peer[1])

    # Connect to ctrl_proxy and perform ML-KEM handshake before data.
    try:
        ctrl_reader, ctrl_writer = await asyncio.open_connection(
            settings.proxy.controller_host,
            settings.proxy.controller_port,
        )
    except OSError as exc:
        log.error("[SW-PROXY] cannot reach ctrl_proxy: %s", exc)
        ovs_writer.close()
        return

    # Generate a random 32-bit connection ID (used in place of dpid pre-Features-Reply)
    conn_id = int.from_bytes(os.urandom(4), "big")

    # Send handshake-mode preamble: PQC\x02 + conn_id
    ctrl_writer.write(_HANDSHAKE_MAGIC + struct.pack("!I", conn_id))
    await ctrl_writer.drain()

    loop = asyncio.get_event_loop()

    # Perform the switch-side ML-KEM handshake — real TCP exchange with ctrl_proxy
    try:
        send_sess, recv_sess = await _sw_pqc_handshake(ctrl_reader, ctrl_writer, conn_id, loop)
    except Exception as exc:
        log.error("[SW-PROXY] PQC handshake failed (conn=%d): %s", conn_id, exc)
        ovs_writer.close()
        ctrl_writer.close()
        return

    # Encryption is active immediately — no plan-API polling needed
    state: dict = {"active": True, "send": send_sess, "recv": recv_sess, "dpid": 0}

    # Run both pipe directions. When EITHER direction ends (one side closed the
    # TCP connection), cancel the other so both sockets are torn down promptly.
    # Without this, the surviving pipe stays blocked on read() forever, leaving
    # the peer socket stuck in CLOSE-WAIT — which makes OVS reconnect, producing
    # "Multiple connections from <dpid>" on Ryu and breaking topology discovery.
    t_out = asyncio.ensure_future(_pipe_ovs_to_ctrl(ovs_reader, ctrl_writer, state))
    t_in  = asyncio.ensure_future(_pipe_ctrl_to_ovs(ctrl_reader, ovs_writer, state))
    try:
        done, pending = await asyncio.wait(
            {t_out, t_in}, return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()
        # Surface any non-cancellation exception for logging
        for t in done:
            exc = t.exception()
            if isinstance(exc, FrameError):
                log.warning("[SW-PROXY] conn=%d closed: %s", conn_id, exc)
            elif exc and not isinstance(exc, asyncio.CancelledError):
                log.debug("[SW-PROXY] conn=%d pipe ended: %s", conn_id, exc)
    finally:
        for t in (t_out, t_in):
            if not t.done():
                t.cancel()
        for w in (ovs_writer, ctrl_writer):
            try:
                if not w.is_closing():
                    w.close()
            except Exception:
                pass
        for w in (ovs_writer, ctrl_writer):
            try:
                await asyncio.wait_for(w.wait_closed(), timeout=2.0)
            except Exception:
                pass
        log.info("[SW-PROXY] conn=%d (dpid=%d) connection closed", conn_id, state["dpid"])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def run() -> None:
    settings = get_settings()
    port = settings.proxy.base_data_port  # single shared port for ALL switches

    server = await asyncio.start_server(
        handle_switch_connection,
        settings.proxy.listen_host,
        port,
    )
    log.info(
        "[SW-PROXY] listening on %s:%d (pool=%d threads) → ctrl_proxy :%d",
        settings.proxy.listen_host, port, _POOL_SIZE, settings.proxy.controller_port,
    )
    async with server:
        await server.serve_forever()


def _raise_fd_limit(target: int = 65536) -> None:
    """Raise soft FD limit — large topologies exceed the default 1024."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = min(target, hard)
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            log.info("[SW-PROXY] raised FD limit %d → %d (hard=%d)", soft, new_soft, hard)
    except Exception as exc:
        log.warning("[SW-PROXY] could not raise FD limit: %s", exc)


def main() -> None:
    configure_logging()
    _raise_fd_limit()
    asyncio.run(run())


if __name__ == "__main__":
    main()
