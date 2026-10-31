"""
PQC-SDN Stack Manager — starts/stops the real proxy stack for evaluation.

Manages: Ryu controller (6653) + ctrl_proxy (6652) + sw_proxy_async (6634).
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import List

_ROOT      = Path(__file__).resolve().parent.parent
_SRC       = _ROOT / "src"
def _find_venv_bin() -> Path:
    """Locate the venv bin dir — checks project root, then parent (SDN-PQC/venv)."""
    for cand in (_ROOT / "venv" / "bin",
                 _ROOT.parent / "venv" / "bin"):
        if (cand / "ryu-manager").exists():
            return cand
    return _ROOT / "venv" / "bin"  # fallback (may not exist)


_VENV_BIN  = _find_venv_bin()
_VENV_PY   = _VENV_BIN / "python3"
_PYTHON    = str(_VENV_PY) if _VENV_PY.exists() else sys.executable
_VENV_RYU  = _VENV_BIN / "ryu-manager"
_RYU_MGR   = str(_VENV_RYU) if _VENV_RYU.exists() else "ryu-manager"
_LOG_DIR   = Path("/tmp/pqc_eval_logs")


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class StackManager:
    PORTS = {"ryu": 6653, "ctrl_proxy": 6652, "sw_proxy": 6634}

    def __init__(self, startup_timeout: float = 25.0, reuse_running: bool = True):
        self._timeout = startup_timeout
        self._reuse   = reuse_running
        self._procs: List[subprocess.Popen] = []
        self._logs:  List = []
        self.is_up  = False
        self._owned = False

    @property
    def ctrl_proxy_port(self) -> int:
        return self.PORTS["ctrl_proxy"]

    @property
    def sw_proxy_port(self) -> int:
        return self.PORTS["sw_proxy"]

    def __enter__(self) -> "StackManager":
        self.start()
        return self

    def __exit__(self, *_):
        if self._owned:
            self.stop()

    def start(self) -> bool:
        if self._reuse and self._all_ports_open():
            print("  [stack] Already running — reusing existing stack ✓")
            self.is_up = True
            self._owned = False
            return True

        print("  [stack] Starting PQC-SDN stack (Ryu + ctrl_proxy + sw_proxy) ...")
        _LOG_DIR.mkdir(exist_ok=True)

        env = {**os.environ, "PYTHONPATH": str(_SRC)}
        env["PATH"] = str(_VENV_BIN) + os.pathsep + env.get("PATH", "")

        self._launch([_RYU_MGR,
                      str(_SRC / "pqc_sdn" / "controller" / "controller.py"),
                      "--observe-links",
                      "--ofp-tcp-listen-port", str(self.PORTS["ryu"])],
                     env, "ryu.log")
        self._launch([_PYTHON, "-m", "pqc_sdn.apps.ctrl_proxy"],
                     env, "ctrl_proxy.log")
        self._launch([_PYTHON, "-m", "pqc_sdn.apps.sw_proxy_async"],
                     env, "sw_proxy.log")

        deadline = time.time() + self._timeout
        while time.time() < deadline:
            if self._all_ports_open():
                print(f"  [stack] All ports open: "
                      f"Ryu:{self.PORTS['ryu']} "
                      f"ctrl_proxy:{self.PORTS['ctrl_proxy']} "
                      f"sw_proxy:{self.PORTS['sw_proxy']} ✓")
                self.is_up = True
                self._owned = True
                return True
            time.sleep(0.5)

        missing = [n for n, p in self.PORTS.items() if not _port_open(p)]
        print(f"  [stack] ⚠ Not fully up after {self._timeout:.0f}s — missing: {missing}")
        self.is_up = len(missing) == 0
        self._owned = True
        return self.is_up

    def stop(self):
        if not self._procs:
            return
        print("  [stack] Stopping PQC-SDN stack ...")
        for p in self._procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                p.wait(timeout=4)
            except Exception:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except Exception:
                    pass
        for f in self._logs:
            try: f.close()
            except: pass
        self._procs.clear()
        self._logs.clear()
        self.is_up = False
        self._owned = False

    def _all_ports_open(self) -> bool:
        return all(_port_open(p) for p in self.PORTS.values())

    def _launch(self, cmd, env, log_name):
        log_file = open(_LOG_DIR / log_name, "w")
        proc = subprocess.Popen(
            cmd, env=env,
            stdout=log_file, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        self._procs.append(proc)
        self._logs.append(log_file)
