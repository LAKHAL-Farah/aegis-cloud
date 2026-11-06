"""Health probes. A probe answers one question: is this component doing its job right now?

Liveness is judged from a heartbeat file (docs/ops-contract.md), not from "the process exists": a detector stuck in
a hung API call is alive to `ps` and dead to us.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Result:
    component: str
    up: bool
    detail: str


def read_heartbeat(path: Path) -> dict | None:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and {"component", "ts", "pid"} <= data.keys() else None


def pid_alive(pid: int) -> bool:
    """Alive means running, not merely present: a killed child whose parent has not collected it is a zombie, and
    os.kill(pid, 0) still succeeds for it (measured: that made a killed detector look alive for up to 20 s)."""
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError):
        return False
    try:
        with open(f"/proc/{int(pid)}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return True                 # no /proc (not Linux): the signal check is all we have


class HeartbeatProbe:
    def __init__(self, component: str, path: Path, max_age_s: float, clock=time.time, alive=pid_alive):
        self.component, self.path, self.max_age_s, self.clock, self.alive = component, Path(path), max_age_s, clock, alive

    def check(self) -> Result:
        hb = read_heartbeat(self.path)
        if hb is None:
            return Result(self.component, False, "no heartbeat file")
        age = self.clock() - float(hb["ts"])
        if age > self.max_age_s:
            return Result(self.component, False, f"heartbeat {age:.0f} s old (limit {self.max_age_s:.0f} s)")
        if not self.alive(hb["pid"]):
            return Result(self.component, False, f"pid {hb['pid']} is gone")
        return Result(self.component, True, f"beat {age:.1f} s ago, pid {hb['pid']}")


class HttpProbe:
    def __init__(self, component: str, url: str, timeout: float = 3.0, opener=urllib.request.urlopen):
        self.component, self.url, self.timeout, self.opener = component, url, timeout, opener

    def check(self) -> Result:
        try:
            with self.opener(self.url, timeout=self.timeout) as resp:
                code = getattr(resp, "status", 200)
            return Result(self.component, code < 400, f"HTTP {code}")
        except Exception as exc:  # noqa: BLE001 - any failure to answer is "down"
            return Result(self.component, False, type(exc).__name__)


class DockerProbe:
    def __init__(self, component: str, container: str, run=subprocess.run):
        self.component, self.container, self.run = component, container, run

    def check(self) -> Result:
        try:
            out = self.run(["docker", "inspect", "-f", "{{.State.Running}}", self.container],
                           capture_output=True, text=True, timeout=5)
        except Exception as exc:  # noqa: BLE001
            return Result(self.component, False, type(exc).__name__)
        up = out.returncode == 0 and out.stdout.strip() == "true"
        return Result(self.component, up, "running" if up else "not running")
