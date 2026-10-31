"""
Controller-side PQC decrypt proxy.

  SwitchProxy (AES-GCM encrypted) ──► CtrlProxy:6652 (decrypts) ──► Ryu:6653

Protocol (PQC\\x02 — handshake-first mode)
------------------------------------------
sw_proxy_async sends preamble PQC\\x02 + conn_id(4), then a length-prefixed
ClientHello. ctrl_proxy runs server_respond(), sends back ServerHello +
Certificate + EncapsulatedKey (each length-prefixed), then derives session
keys from the shared secret and begins encrypting/decrypting data immediately.

After the real dpid is resolved from a decrypted Features-Reply, ctrl_proxy
registers the session keys with plan_api so the Ryu dashboard knows the
session exists.

Legacy protocol (PQC\\x00 — plan-poll mode)
--------------------------------------------
Still supported for backward compat. ctrl_proxy polls plan_api for pre-computed
keys after resolving the dpid from the plaintext stream.

Usage:
  python -m pqc_sdn.apps.ctrl_proxy
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import struct
import urllib.request
from typing import Optional, Tuple

from pqc_sdn.logging_config import configure_logging, get_logger
from pqc_sdn.settings import get_settings
from pqc_sdn.tls.frames import (
    decode_frame, encode_frame, packet_from_frame,
    CIPHER_ID_TO_NAME, CIPHER_NAME_TO_ID, CIPHER_AES_256_GCM,
)
from pqc_sdn.exceptions import FrameError, HandshakeError
from pqc_sdn.policy.engine import select_frame_cipher
from pqc_sdn.tls.session import SecureSession, MultiCipherSession, derive_directional_keys

log = get_logger("pqc.ctrl_proxy")

# ── Persistent identity for certificate pinning ──────────────────────────────
# Loaded from disk (created on first start) so the public key is stable across
# restarts; switch proxies pin it (settings.proxy.identity_public_key_file).
from pqc_sdn.tls.identity import load_or_create_identity

_CTRL_IDENTITY = load_or_create_identity()


def get_identity_key() -> str:
    """Return the hex-encoded identity public key for pinning configuration."""
    return _CTRL_IDENTITY.public_key.hex()


_PREAMBLE_MAGIC   = b"PQC\x00"   # legacy: poll plan_api for keys
_HANDSHAKE_MAGIC  = b"PQC\x02"   # new: perform KEM handshake inline
_PREAMBLE_LEN     = 8            # 4 magic + 4 dpid/conn_id
_WIRE_HDR_LEN     = 22           # v2: HEADER(10) + NONCE(12) — minimum decodable wire frame
_OF_HDR_LEN       = 8            # OpenFlow fixed header


def _extract_dpid_from_of(data: bytes) -> int | None:
    """
    Scan a plaintext OpenFlow buffer for Features-Reply (type=6) and return
    the 64-bit datapath_id.

    OF 1.3 Features-Reply layout:
      byte 0: version, byte 1: type=6, bytes 2-3: length,
      bytes 4-7: xid, bytes 8-15: datapath_id (uint64 big-endian)
    """
    i = 0
    while i + 16 <= len(data):
        if data[i + 1] == 6:
            return struct.unpack_from("!Q", data, i + 8)[0]
        frame_len = struct.unpack_from("!H", data, i + 2)[0]
        if frame_len < 8:
            break
        i += frame_len
    return None


# ---------------------------------------------------------------------------
# Plan API helpers (legacy plan-poll mode)
# ---------------------------------------------------------------------------

def _cafile() -> Optional[str]:
    settings = get_settings()
    path = settings.proxy.tls_cert
    if not os.path.isabs(path):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        path = os.path.join(root, path)
    return path if os.path.exists(path) else None


def _fetch_plans(dpid: int) -> list:
    settings = get_settings()
    url = (f"https://{settings.proxy.controller_host}"
           f":{settings.proxy.controller_api_port}/pqc/proxy/plans/{dpid}")
    try:
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {settings.proxy.api_token}")
        ca = _cafile()
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=2, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:
        log.debug("plan fetch dpid=%d: %s", dpid, exc)
        return []


def _sessions_from_plans(plans: list) -> Optional[Tuple[SecureSession, SecureSession]]:
    """
    Return (decrypt_session, encrypt_session) from the active TUNNEL plan.

    Switch proxy:  encrypts with send_key_hex,  decrypts with recv_key_hex
    ctrl_proxy:    decrypts with send_key_hex,  encrypts with recv_key_hex
    """
    for p in plans:
        if p.get("role") == "tunnel" and p.get("active"):
            sw_send = bytes.fromhex(p["send_key_hex"])   # switch encrypts → ctrl decrypts
            sw_recv = bytes.fromhex(p["recv_key_hex"])   # ctrl encrypts  → switch decrypts
            kid, ctx = p.get("key_id", p["ctx"]), p["ctx"]
            # decrypt_sess: recv_key=sw_send so .decrypt() uses sw_send
            decrypt_sess = SecureSession(ctx, sw_recv, sw_send, kid, "ctrl_proxy", "switch")
            # encrypt_sess: send_key=sw_recv so .encrypt() uses sw_recv
            encrypt_sess = SecureSession(ctx, sw_recv, sw_send, kid, "ctrl_proxy", "switch")
            return decrypt_sess, encrypt_sess
    return None


# ---------------------------------------------------------------------------
# Handshake helpers (new PQC\x02 mode)
# ---------------------------------------------------------------------------

_KEM_ORDER = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]


def _allowed_kem_variants() -> set:
    """KEM variants at or above the deployment floor (crypto.min_control_plane_kem,
    defaulting to crypto.control_plane_kem). Rejects tier downgrades."""
    crypto = get_settings().crypto
    floor = crypto.min_control_plane_kem or crypto.control_plane_kem
    return set(_KEM_ORDER[_KEM_ORDER.index(floor):])


async def _read_msg(reader: asyncio.StreamReader, timeout: float = 10.0) -> bytes:
    """Read one length-prefixed message (4-byte big-endian length + payload)."""
    hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    msg_len = struct.unpack("!I", hdr)[0]
    if msg_len == 0 or msg_len > 1_048_576:
        raise ValueError(f"invalid handshake message length: {msg_len}")
    return await asyncio.wait_for(reader.readexactly(msg_len), timeout=timeout)


async def _ctrl_pqc_handshake(
    sw_reader: asyncio.StreamReader,
    sw_writer: asyncio.StreamWriter,
    conn_id: int,
) -> tuple[SecureSession, SecureSession, dict]:
    """Server-side ML-KEM handshake with sw_proxy_async.

    Reads ClientHello, calls server_respond(), sends back ServerHello +
    Certificate + EncapsulatedKey, then derives session keys from the shared
    secret.  Returns (dec_sess, enc_sess, kem_info) where dec_sess is used to
    decrypt frames from the switch and enc_sess to encrypt frames to the switch.

    kem_info carries the key material needed to register the session with
    plan_api once the real dpid is sniffed from the decrypted OF stream.
    """
    from pqc_sdn.tls.messages import ClientHello
    from pqc_sdn.tls.handshake import HybridHandshake

    loop = asyncio.get_event_loop()

    ch_raw = await _read_msg(sw_reader)

    ctrl_hs = HybridHandshake(f"ctrl-{conn_id}", identity=_CTRL_IDENTITY)
    allowed = _allowed_kem_variants()

    def _respond(raw: bytes):
        hello = ClientHello.deserialize(raw)
        return ctrl_hs.server_respond(hello, allowed_variants=allowed)

    s_hello, cert, encap, shared_secret = await loop.run_in_executor(
        None, _respond, ch_raw
    )

    for msg in (s_hello, cert, encap):
        blob = msg.serialize()
        sw_writer.write(struct.pack("!I", len(blob)) + blob)
    await sw_writer.drain()

    # Derive the same directional keys the switch derives
    sw_send, sw_recv = derive_directional_keys(shared_secret, s_hello.session_id)
    key_id = f"key-{s_hello.session_id}"

    # ctrl perspective: send_key=sw_recv (ctrl encrypts → switch decrypts with recv_key)
    #                   recv_key=sw_send (ctrl decrypts ← switch encrypted with send_key)
    # One session object serves both directions (independent send/recv keys
    # and sequence counters).
    dec_sess = enc_sess = MultiCipherSession(
        s_hello.session_id, sw_recv, sw_send, key_id, "ctrl_proxy", f"sw-{conn_id}"
    )

    log.info("[CTRL-PROXY] conn=%d server handshake OK session=%s", conn_id, s_hello.session_id)

    kem_info = {
        "session_id":      s_hello.session_id,
        "kem_variant":     s_hello.ml_kem_variant,
        # Keys are NOT transmitted — proxies already have them from the handshake.
        # Only metadata is sent to plan_api for dashboard visibility.
        "key_id":          key_id,
        "handshake":       ctrl_hs,
    }
    return dec_sess, enc_sess, kem_info


async def _verify_client_auth(sw_reader: asyncio.StreamReader, dec_sess, ctrl_hs) -> str:
    """Read the first tunnel frame and verify the switch-proxy's ClientAuth.

    Runs before any connection to Ryu is opened, so an unauthenticated peer
    never reaches the controller. Returns the authenticated sender id.
    """
    from pqc_sdn.tls.identity import load_authorized_switch_keys
    from pqc_sdn.tls.messages import ClientAuth

    keys = load_authorized_switch_keys()
    if not keys:
        raise HandshakeError("mutual auth enabled but no authorized switch keys configured")
    hdr = await asyncio.wait_for(sw_reader.readexactly(4), timeout=10.0)
    total_len = struct.unpack("!I", hdr)[0]
    if total_len < _WIRE_HDR_LEN or total_len > 131072:
        raise FrameError(f"invalid ClientAuth frame length {total_len}")
    frame = hdr + await asyncio.wait_for(sw_reader.readexactly(total_len - 4), timeout=10.0)
    wf = decode_frame(frame)
    cipher_name = CIPHER_ID_TO_NAME.get(wf.cipher_id)
    if cipher_name is None:
        raise FrameError(f"unknown cipher_id {wf.cipher_id}")
    plain = dec_sess.decrypt(packet_from_frame(wf, dec_sess.key_id), cipher_name=cipher_name)
    if not plain.startswith(ClientAuth.MAGIC):
        raise HandshakeError("first tunnel frame is not ClientAuth")
    auth = ClientAuth.deserialize(plain[len(ClientAuth.MAGIC):])
    await asyncio.get_event_loop().run_in_executor(
        None, ctrl_hs.verify_client_auth, auth, keys
    )
    return auth.sender_id


def _register_session_sync(
    dpid: int,
    session_id: str,
    kem_variant: str,
    key_id: str,
) -> None:
    """Call POST /pqc/sessions/register on plan_api to record session metadata.

    This is non-critical: if plan_api is unreachable the proxies still function
    correctly (they have the keys already). Only metadata is transmitted —
    session keys NEVER leave the proxy process.
    """
    settings = get_settings()
    url = (f"https://{settings.proxy.controller_host}"
           f":{settings.proxy.controller_api_port}/pqc/sessions/register")
    body = json.dumps({
        "dpid":            dpid,
        "session_id":      session_id,
        "kem_variant":     kem_variant,
        "key_id":          key_id,
    }).encode()
    try:
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {settings.proxy.api_token}",
            },
        )
        ca = _cafile()
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=2, context=ctx):
            log.info("[CTRL-PROXY] dpid=%d session registered with plan_api", dpid)
    except Exception as exc:
        log.debug("[CTRL-PROXY] dpid=%d session registration failed (non-critical): %s", dpid, exc)


# ---------------------------------------------------------------------------
# Pipe coroutines
# ---------------------------------------------------------------------------

async def _pipe_sw_to_ryu(
    sw_reader: asyncio.StreamReader,
    ryu_writer: asyncio.StreamWriter,
    state: dict,
    on_dpid_resolved=None,
) -> None:
    """Decrypt wire frames from switch proxy → plaintext to Ryu.

    In handshake mode (state["active"]=True from the start) the buffer arrives
    already encrypted; dpid is sniffed from each decrypted plaintext frame.
    In legacy plan-poll mode (state["active"]=False initially) the buffer is
    plaintext until activation; dpid is sniffed directly from the buffer.
    """
    buf = b""
    bufsz = get_settings().proxy.read_buffer_size
    _dpid_sniffed = state["dpid"] != 0
    while True:
        chunk = await sw_reader.read(bufsz)
        if not chunk:
            break
        buf += chunk

        if not state["active"]:
            # Legacy plan-poll mode only (disabled by default): plaintext until
            # the plan arrives.
            if not _dpid_sniffed and on_dpid_resolved is not None:
                real_dpid = _extract_dpid_from_of(buf)
                if real_dpid is not None:
                    _dpid_sniffed = True
                    await on_dpid_resolved(real_dpid)
            ryu_writer.write(buf)
            await ryu_writer.drain()
            buf = b""
            continue

        while len(buf) >= _WIRE_HDR_LEN:
            total_len = struct.unpack_from("!I", buf, 0)[0]
            if total_len < _WIRE_HDR_LEN or total_len > 131072:
                # Never forward unauthenticated bytes to the controller.
                raise FrameError(f"invalid wire frame length {total_len}")
            if len(buf) < total_len:
                break
            frame_bytes, buf = buf[:total_len], buf[total_len:]
            try:
                wf = decode_frame(frame_bytes)
                cipher_name = CIPHER_ID_TO_NAME.get(wf.cipher_id)
                if cipher_name is None:
                    raise FrameError(f"unknown cipher_id {wf.cipher_id}")
                pkt = packet_from_frame(wf, state["dec"].key_id)
                if isinstance(state["dec"], MultiCipherSession):
                    plain = state["dec"].decrypt(pkt, cipher_name=cipher_name)
                else:
                    plain = state["dec"].decrypt(pkt)   # legacy plan-poll session
            except Exception as exc:
                # Authentication/replay failure is fatal, as in TLS.
                log.warning("[CTRL-PROXY] rejecting frame and closing: %s", exc)
                raise FrameError(str(exc)) from exc
            # Sniff decrypted plaintext for dpid (handshake mode: encrypted from start)
            if not _dpid_sniffed and on_dpid_resolved is not None:
                real_dpid = _extract_dpid_from_of(plain)
                if real_dpid is not None:
                    _dpid_sniffed = True
                    await on_dpid_resolved(real_dpid)
            ryu_writer.write(plain)
            await ryu_writer.drain()


async def _pipe_ryu_to_sw(
    ryu_reader: asyncio.StreamReader,
    sw_writer: asyncio.StreamWriter,
    state: dict,
) -> None:
    """Encrypt Ryu plaintext OF frames → wire frames to switch proxy."""
    _fixed_cipher = os.environ.get("PQC_FIXED_CIPHER")
    buf = b""
    bufsz = get_settings().proxy.read_buffer_size
    while True:
        chunk = await ryu_reader.read(bufsz)
        if not chunk:
            break
        buf += chunk

        if not state["active"]:
            sw_writer.write(buf)
            await sw_writer.drain()
            buf = b""
            continue

        while len(buf) >= _OF_HDR_LEN:
            of_len = struct.unpack_from("!H", buf, 2)[0]
            if of_len < 8 or of_len > 65536:
                raise FrameError(f"invalid OpenFlow length {of_len} from controller")
            if len(buf) < of_len:
                break
            frame, buf = buf[:of_len], buf[of_len:]
            if isinstance(state["enc"], MultiCipherSession):
                # PACKET_OUT inherits the carried packet's DSCP class; FLOW_MOD
                # and other controller messages are CS6 control traffic.
                cipher_name = _fixed_cipher or select_frame_cipher(frame)
                pkt = state["enc"].encrypt(frame, cipher_name=cipher_name)
                sw_writer.write(encode_frame(pkt, cipher_id=CIPHER_NAME_TO_ID[cipher_name]))
            else:
                # Legacy plan-poll session: single-cipher AES-256-GCM.
                pkt = state["enc"].encrypt(frame)
                sw_writer.write(encode_frame(pkt, cipher_id=CIPHER_AES_256_GCM))
            await sw_writer.drain()


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

async def handle_connection(
    sw_reader: asyncio.StreamReader,
    sw_writer: asyncio.StreamWriter,
) -> None:
    settings = get_settings()

    # 1. Read preamble: 4 magic bytes + 4 dpid/conn_id bytes
    try:
        preamble = await asyncio.wait_for(sw_reader.readexactly(_PREAMBLE_LEN), timeout=10.0)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        log.warning("ctrl_proxy: no preamble received, closing")
        sw_writer.close()
        return

    magic   = preamble[:4]
    conn_id = struct.unpack_from("!I", preamble, 4)[0]

    handshake_mode = (magic == _HANDSHAKE_MAGIC)

    if magic not in (_PREAMBLE_MAGIC, _HANDSHAKE_MAGIC):
        log.warning("ctrl_proxy: bad magic %r, closing", magic)
        sw_writer.close()
        return
    if not handshake_mode and not settings.proxy.allow_legacy_plan_mode:
        log.warning("ctrl_proxy: legacy plan-poll mode disabled, closing (conn/dpid=%d)",
                    conn_id)
        sw_writer.close()
        return

    log.info("[CTRL-PROXY] connection accepted (mode=%s conn/dpid=%d)",
             "handshake" if handshake_mode else "plan-poll", conn_id)

    # 2. Handshake mode: exchange KEM messages before connecting to Ryu
    dec_sess = enc_sess = None
    kem_info: dict = {}

    if handshake_mode:
        try:
            dec_sess, enc_sess, kem_info = await _ctrl_pqc_handshake(
                sw_reader, sw_writer, conn_id
            )
        except Exception as exc:
            log.error("[CTRL-PROXY] handshake failed (conn=%d): %s", conn_id, exc)
            sw_writer.close()
            return
        if settings.proxy.mutual_auth:
            try:
                peer = await _verify_client_auth(sw_reader, dec_sess, kem_info["handshake"])
                log.info("[CTRL-PROXY] conn=%d switch proxy authenticated (%s)", conn_id, peer)
            except Exception as exc:
                log.error("[CTRL-PROXY] client authentication failed (conn=%d): %s",
                          conn_id, exc)
                sw_writer.close()
                return

    # 3. Connect to Ryu
    try:
        ryu_reader, ryu_writer = await asyncio.open_connection(
            settings.proxy.controller_host, settings.proxy.ryu_port
        )
    except OSError as exc:
        log.error("cannot reach Ryu: %s", exc)
        sw_writer.close()
        return

    # 4. Shared state — active=True immediately in handshake mode
    state: dict = {
        "active": handshake_mode,
        "dec":    dec_sess,
        "enc":    enc_sess,
        "dpid":   0 if handshake_mode else conn_id,
    }

    # 5. Coroutines for key activation / session registration / refresh

    async def _activate_encryption() -> None:
        loop = asyncio.get_event_loop()
        for _ in range(20):
            plans = await loop.run_in_executor(None, _fetch_plans, state["dpid"])
            result = _sessions_from_plans(plans)
            if result:
                state["dec"], state["enc"] = result
                state["active"] = True
                log.info("[CTRL-PROXY] dpid=%d encryption ACTIVE key=%s",
                         state["dpid"], state["dec"].key_id)
                return
            await asyncio.sleep(0.5)
        # Never fall back to plaintext: drop the connection instead.
        log.warning("[CTRL-PROXY] dpid=%d no active plan after 10s — closing",
                    state["dpid"])
        sw_writer.close()

    async def _register_session(real_dpid: int) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, _register_session_sync,
            real_dpid,
            kem_info["session_id"],
            kem_info["kem_variant"],
            kem_info["key_id"],
        )

    async def _refresh_keys() -> None:
        # In handshake mode, session keys are derived live during the ML-KEM
        # handshake and both sessions are MultiCipherSession instances that
        # support per-frame cipher selection. The plan-API path returns plain
        # SecureSession objects (no cipher_name kwarg), so swapping them in would
        # break the reverse (Ryu→switch) pipe: SecureSession.encrypt() rejects
        # cipher_name and every frame gets dropped, killing the OF channel.
        # Therefore plan-based key rotation only applies to legacy (plan) mode.
        if handshake_mode:
            return
        loop = asyncio.get_event_loop()
        interval = settings.proxy.plan_poll_interval_seconds
        while True:
            await asyncio.sleep(interval)
            if not state["active"] or not state["dpid"]:
                continue
            plans = await loop.run_in_executor(None, _fetch_plans, state["dpid"])
            result = _sessions_from_plans(plans)
            if result:
                new_dec, new_enc = result
                if new_dec.key_id != state["dec"].key_id:
                    # Atomic swap: update both sessions together so pipe
                    # coroutines never see mismatched dec/enc sessions.
                    state.update({"dec": new_dec, "enc": new_enc})
                    log.info("[CTRL-PROXY] dpid=%d key rotated → %s",
                             state["dpid"], new_dec.key_id)

    activate_task: Optional[asyncio.Task] = None

    async def _on_dpid_resolved(real_dpid: int) -> None:
        nonlocal activate_task
        if state["dpid"] == real_dpid:
            return
        state["dpid"] = real_dpid
        log.info("[CTRL-PROXY] real dpid=%d resolved from OF Features-Reply", real_dpid)
        if handshake_mode:
            # Keys already derived; optionally register with plan_api for
            # dashboard visibility.
            if settings.proxy.register_sessions:
                asyncio.create_task(_register_session(real_dpid))
        else:
            activate_task = asyncio.create_task(_activate_encryption())

    # Legacy mode: start activation immediately if preamble already had real dpid
    if not handshake_mode and conn_id != 0:
        activate_task = asyncio.create_task(_activate_encryption())

    refresh_task = asyncio.create_task(_refresh_keys())

    # Run both pipe directions. When EITHER ends, cancel the other so both
    # sockets tear down promptly — otherwise the surviving pipe blocks on read()
    # forever, leaving the peer socket in CLOSE-WAIT. That makes OVS reconnect,
    # producing "Multiple connections from <dpid>" on Ryu and breaking topology.
    t_sw = asyncio.ensure_future(_pipe_sw_to_ryu(sw_reader, ryu_writer, state, _on_dpid_resolved))
    t_ryu = asyncio.ensure_future(_pipe_ryu_to_sw(ryu_reader, sw_writer, state))
    try:
        done, pending = await asyncio.wait(
            {t_sw, t_ryu}, return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()
        for t in done:
            exc = t.exception()
            if isinstance(exc, FrameError):
                log.warning("[CTRL-PROXY] conn=%d closed: %s", conn_id, exc)
            elif exc and not isinstance(exc, asyncio.CancelledError):
                log.debug("[CTRL-PROXY] conn=%d pipe ended: %s", conn_id, exc)
    finally:
        # Guaranteed cleanup — runs even if this coroutine is cancelled during
        # Mininet teardown. Without this, sockets leak until EMFILE (Errno 24).
        for t in (t_sw, t_ryu):
            if not t.done():
                t.cancel()
        refresh_task.cancel()
        if activate_task:
            activate_task.cancel()
        for w in (sw_writer, ryu_writer):
            try:
                if not w.is_closing():
                    w.close()
            except Exception:
                pass
        for w in (sw_writer, ryu_writer):
            try:
                await asyncio.wait_for(w.wait_closed(), timeout=2.0)
            except Exception:
                pass
        log.info("[CTRL-PROXY] conn/dpid=%d connection closed", state["dpid"] or conn_id)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def run() -> None:
    settings = get_settings()
    port = settings.proxy.ctrl_proxy_port
    server = await asyncio.start_server(handle_connection, settings.proxy.ctrl_listen_host, port)
    log.info("[CTRL-PROXY] listening :%-5d  →  Ryu :%d", port, settings.proxy.ryu_port)
    async with server:
        await server.serve_forever()


def _raise_fd_limit(target: int = 65536) -> None:
    """Raise the soft file-descriptor limit up to the hard limit.

    Each switch connection through the proxy holds multiple sockets; large
    fat-tree topologies (k=8 → 80 switches) plus LLDP discovery can exceed
    the default soft limit of 1024, causing EMFILE (Errno 24) and dropped
    connections that break topology convergence.
    """
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = min(target, hard)
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            log.info("[CTRL-PROXY] raised FD limit %d → %d (hard=%d)", soft, new_soft, hard)
    except Exception as exc:
        log.warning("[CTRL-PROXY] could not raise FD limit: %s", exc)


def main() -> None:
    configure_logging()
    _raise_fd_limit()
    asyncio.run(run())


if __name__ == "__main__":
    main()
