"""
Shared helpers for live-stack measurements across evaluation tables.

These functions connect to the ACTUAL running proxy stack (sw_proxy:6634,
ctrl_proxy:6652, Ryu:6653) and measure real end-to-end behavior.

Used by Tables 2, 3, 4, 7, 8 and topo_comparison to add live-stack
sections when the stack is up.

Architecture under test:
  OVS switch → TCP :6634 → sw_proxy_async (ML-KEM handshake + AES-GCM encrypt)
               → TCP :6652 → ctrl_proxy (decrypt)
               → TCP :6653 → Ryu controller

All functions gracefully return failure dicts when the stack is down,
so callers can use them without try/except.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from typing import Optional

# Ports (match settings.py defaults)
SW_PROXY_PORT = 6634
CTRL_PROXY_PORT = 6652
RYU_PORT = 6653
METRICS_PORT = 9101


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def stack_is_up() -> bool:
    """Return True if the full PQC-SDN stack is running (all 3 ports open)."""
    return all(_port_open(p) for p in (SW_PROXY_PORT, CTRL_PROXY_PORT, RYU_PORT))


def stack_status() -> dict:
    """Return detailed stack status for consistent reporting across tables."""
    status = {
        "sw_proxy": _port_open(SW_PROXY_PORT),
        "ctrl_proxy": _port_open(CTRL_PROXY_PORT),
        "ryu": _port_open(RYU_PORT),
        "metrics": _port_open(METRICS_PORT),
    }
    status["all_up"] = all(status[k] for k in ("sw_proxy", "ctrl_proxy", "ryu"))
    sessions = scrape_prometheus_metric("pqc_active_sessions") if status["metrics"] else None
    status["active_sessions"] = sessions
    return status


# ═══════════════════════════════════════════════════════════════════
# Live handshake measurement
# ═══════════════════════════════════════════════════════════════════


def live_handshake_as_switch(timeout: float = 15.0) -> dict:
    """Connect to sw_proxy:6634 as an OVS switch and measure the end-to-end
    handshake time.

    When an OVS switch connects to sw_proxy, the proxy immediately:
      1. Opens TCP to ctrl_proxy:6652
      2. Sends PQC\\x02 preamble + ClientHello
      3. Receives ServerHello + Certificate + EncapsulatedKey
      4. Derives session keys
      5. Starts encrypting/decrypting traffic

    From the switch's perspective, the handshake is invisible — it just
    connects TCP and starts receiving OpenFlow Hello. We measure the time
    from TCP connect to receiving the first OpenFlow message back (Hello),
    which includes the entire PQC handshake + Ryu registration.

    Returns: {handshake_ms, first_msg_type, first_msg_len, success}
    """
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection(("127.0.0.1", SW_PROXY_PORT), timeout=timeout)
        sock.settimeout(timeout)

        # Send an OF 1.3 Hello as the switch would
        of_hello = struct.pack("!BBHI", 0x04, 0x00, 0x0008, 0x00000001)  # v1.3 Hello
        sock.sendall(of_hello)

        # Wait for the first response — this arrives only AFTER sw_proxy completes
        # its handshake with ctrl_proxy AND ctrl_proxy connects to Ryu AND Ryu
        # sends back its Hello through the encrypted tunnel.
        response = b""
        while len(response) < 8:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        elapsed_ms = (time.perf_counter() - t0) * 1000

        result = {
            "handshake_ms": round(elapsed_ms, 2),
            "success": len(response) >= 8,
        }

        if len(response) >= 8:
            version, msg_type, msg_len = struct.unpack_from("!BBH", response, 0)
            result["first_msg_type"] = msg_type
            result["first_msg_len"] = msg_len
            result["of_version"] = version
            result["response_bytes"] = len(response)

        sock.close()
        return result

    except Exception as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return {"handshake_ms": round(elapsed_ms, 2), "success": False, "error": str(e)}


def live_tunnel_throughput(n_frames: int = 100, payload_size: int = 72) -> dict:
    """Connect to sw_proxy:6634, complete handshake, then measure throughput
    of sending N OpenFlow frames through the real encrypted tunnel.

    Each frame goes: switch → sw_proxy (encrypt) → ctrl_proxy (decrypt) → Ryu.
    We measure wall time from first send to receiving the echo responses.

    Uses OF Echo-Request/Reply for bidirectional measurement — Ryu echoes
    back each request, so we measure the full round-trip through encryption.

    Returns: {frames_sent, frames_received, wall_ms, throughput_fps,
              throughput_mbps, bytes_sent, bytes_received}
    """
    try:
        sock = socket.create_connection(("127.0.0.1", SW_PROXY_PORT), timeout=15)
        sock.settimeout(15)

        # Send OF Hello
        of_hello = struct.pack("!BBHI", 0x04, 0x00, 0x0008, 0x00000001)
        sock.sendall(of_hello)

        # Wait for Ryu's Hello back (handshake complete)
        hello_resp = b""
        while len(hello_resp) < 8:
            chunk = sock.recv(4096)
            if not chunk:
                break
            hello_resp += chunk

        if len(hello_resp) < 8:
            sock.close()
            return {"success": False, "error": "No Hello response — handshake failed"}

        # Now send N Echo-Request frames and measure throughput
        # OF Echo-Request: type=2, with optional payload
        xid = 100
        frames_sent = 0
        bytes_sent = 0

        t0 = time.perf_counter()

        for i in range(n_frames):
            xid_val = xid + i
            # Build Echo-Request with payload
            payload = os.urandom(max(0, payload_size - 8))  # -8 for OF header
            of_len = 8 + len(payload)
            frame = struct.pack("!BBHI", 0x04, 0x02, of_len, xid_val) + payload
            sock.sendall(frame)
            frames_sent += 1
            bytes_sent += len(frame)

        # Read Echo-Reply responses
        sock.settimeout(10)
        frames_received = 0
        bytes_received = 0
        recv_buf = b""

        try:
            while frames_received < n_frames:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                recv_buf += chunk
                bytes_received += len(chunk)

                # Parse OF messages from buffer
                while len(recv_buf) >= 8:
                    _, msg_type, msg_len = struct.unpack_from("!BBH", recv_buf, 0)
                    if msg_len < 8 or len(recv_buf) < msg_len:
                        break
                    if msg_type == 3:  # Echo-Reply
                        frames_received += 1
                    recv_buf = recv_buf[msg_len:]
        except socket.timeout:
            pass

        wall_ms = (time.perf_counter() - t0) * 1000
        sock.close()

        throughput_fps = frames_sent / (wall_ms / 1000) if wall_ms > 0 else 0
        throughput_mbps = (bytes_sent * 8) / (wall_ms / 1000) / 1_000_000 if wall_ms > 0 else 0

        return {
            "success": True,
            "frames_sent": frames_sent,
            "frames_received": frames_received,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "wall_ms": round(wall_ms, 2),
            "throughput_fps": round(throughput_fps, 0),
            "throughput_mbps": round(throughput_mbps, 2),
            "payload_size": payload_size,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def scrape_prometheus_metric(metric_name: str) -> Optional[float]:
    """Scrape a single Prometheus metric value from :9101/metrics."""
    import urllib.request
    try:
        raw = urllib.request.urlopen(
            f"http://127.0.0.1:{METRICS_PORT}/metrics", timeout=2
        ).read().decode()
        for line in raw.splitlines():
            if line.startswith(f"{metric_name} "):
                return float(line.split()[1])
    except Exception:
        pass
    return None


def scrape_prometheus_labels(metric_prefix: str) -> list[dict]:
    """Scrape all lines matching a metric prefix, returning labels and values.

    Returns: [{"labels": {"src_ip": "10.0.0.1", ...}, "value": 1.0}, ...]
    """
    import urllib.request
    results = []
    try:
        raw = urllib.request.urlopen(
            f"http://127.0.0.1:{METRICS_PORT}/metrics", timeout=2
        ).read().decode()
        for line in raw.splitlines():
            if line.startswith("#") or not line.startswith(metric_prefix):
                continue
            # Parse: metric_name{label1="val1",label2="val2"} value
            if "{" in line:
                labels_str = line.split("{")[1].split("}")[0]
                value = float(line.split("}")[-1].strip())
                labels = {}
                for pair in labels_str.split(","):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        labels[k.strip()] = v.strip().strip('"')
                results.append({"labels": labels, "value": value})
            else:
                parts = line.split()
                if len(parts) >= 2:
                    results.append({"labels": {}, "value": float(parts[1])})
    except Exception:
        pass
    return results


# ═══════════════════════════════════════════════════════════════════
# Live file transfer through real proxy tunnel
# ═══════════════════════════════════════════════════════════════════

def live_file_transfer(file_size: int = 102400, timeout: float = 20.0) -> dict:
    """Connect to sw_proxy:6634, complete handshake, then transfer a file
    through the real encrypted tunnel using OF Vendor messages.

    The data path is:
      test client → sw_proxy (encrypt) → ctrl_proxy (decrypt) → Ryu
    Ryu doesn't know what to do with Vendor messages but processes them
    without error. We measure the send throughput through the real tunnel.

    For bidirectional verification, we also measure how many Echo-Requests
    get echoed back through the encrypted return path.

    Returns: {success, bytes_sent, wire_bytes, wall_ms, throughput_mbps}
    """
    try:
        sock = socket.create_connection(("127.0.0.1", SW_PROXY_PORT), timeout=timeout)
        sock.settimeout(timeout)

        # Complete handshake via OF Hello exchange
        of_hello = struct.pack("!BBHI", 0x04, 0x00, 0x0008, 0x00000001)
        sock.sendall(of_hello)

        hello_resp = b""
        while len(hello_resp) < 8:
            chunk = sock.recv(4096)
            if not chunk:
                break
            hello_resp += chunk

        if len(hello_resp) < 8:
            sock.close()
            return {"success": False, "error": "Handshake failed — no Hello response"}

        # Generate file data and send as chunked OF Experimenter messages
        # (type=0x04 for OF1.3 Experimenter — controller ignores unknown experimenter IDs)
        file_data = os.urandom(file_size)
        chunk_size = 1024  # match Table 7's chunk size
        chunks = [file_data[i:i + chunk_size] for i in range(0, file_size, chunk_size)]

        bytes_sent = 0
        wire_bytes = 0
        t0 = time.perf_counter()

        for chunk in chunks:
            # Build as OF Echo-Request (type=2) so we can count echoes back
            of_len = 8 + len(chunk)
            frame = struct.pack("!BBHI", 0x04, 0x02, of_len, 0xFFFF) + chunk
            sock.sendall(frame)
            bytes_sent += len(chunk)
            wire_bytes += len(frame)

        # Count echo replies to verify bidirectional tunnel
        sock.settimeout(5)
        echoes = 0
        recv_buf = b""
        try:
            while echoes < len(chunks):
                data = sock.recv(65536)
                if not data:
                    break
                recv_buf += data
                while len(recv_buf) >= 8:
                    _, msg_type, msg_len = struct.unpack_from("!BBH", recv_buf, 0)
                    if msg_len < 8 or len(recv_buf) < msg_len:
                        break
                    if msg_type == 3:  # Echo-Reply
                        echoes += 1
                    recv_buf = recv_buf[msg_len:]
        except socket.timeout:
            pass

        wall_ms = (time.perf_counter() - t0) * 1000
        sock.close()

        throughput_mbps = (bytes_sent * 8 / 1_000_000) / (wall_ms / 1000) if wall_ms > 0 else 0

        return {
            "success": True,
            "file_size": file_size,
            "bytes_sent": bytes_sent,
            "wire_bytes": wire_bytes,
            "chunks_sent": len(chunks),
            "echoes_received": echoes,
            "wall_ms": round(wall_ms, 2),
            "throughput_mbps": round(throughput_mbps, 2),
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
