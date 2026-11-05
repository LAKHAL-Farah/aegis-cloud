"""The watchdog: probe, record, optionally heal. It is a separate process on purpose: a component cannot report
its own death.

* Every check appends ONE line to health.jsonl: {"ts", "components": {name: {"up", "detail"}}}. The SLO reads that.
* Healing is a restart, rate-limited. A component that keeps dying is a bug to read about, not a loop to run, so
  after `max_restarts` in `window_s` the watchdog stops restarting and says so (events.jsonl, action "gave-up").
* It publishes `Aegis/Pipeline ComponentUp` to CloudWatch when asked. The alarm on that metric treats missing data
  as breaching, so the watchdog dying also raises the alarm (a dead-man's switch).
"""
from __future__ import annotations

import json
import time
from collections import deque
from pathlib import Path

from .probes import Result

NAMESPACE = "Aegis/Pipeline"


def _append(path: Path, rec: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")


class Healer:
    def __init__(self, component: str, restart, max_restarts: int = 3, window_s: float = 600.0, clock=time.time):
        self.component, self.restart, self.max, self.window, self.clock = component, restart, max_restarts, window_s, clock
        self._times: deque[float] = deque()

    def allowed(self) -> bool:
        now = self.clock()
        while self._times and now - self._times[0] > self.window:
            self._times.popleft()
        return len(self._times) < self.max

    def attempt(self) -> tuple[str, bool, str]:
        """(action, ok, detail). action is "restart" or "gave-up"."""
        if not self.allowed():
            return "gave-up", False, f"{self.max} restarts in {self.window:.0f} s: needs a person"
        self._times.append(self.clock())
        try:
            ok = bool(self.restart())
            return "restart", ok, "restarted" if ok else "restart command failed"
        except Exception as exc:  # noqa: BLE001
            return "restart", False, f"{type(exc).__name__}: {exc}"


class Watchdog:
    def __init__(self, probes: list, state_dir: Path, healers: dict | None = None, publisher=None, clock=time.time):
        self.probes, self.dir, self.healers, self.publisher, self.clock = probes, Path(state_dir), healers or {}, publisher, clock

    @property
    def health_log(self) -> Path:
        return self.dir / "health.jsonl"

    @property
    def events_log(self) -> Path:
        return self.dir / "events.jsonl"

    def check(self) -> list[Result]:
        results = [p.check() for p in self.probes]
        _append(self.health_log, {"ts": self.clock(), "components": {r.component: {"up": r.up, "detail": r.detail} for r in results}})
        if self.publisher:
            try:
                self.publisher.publish(results)
            except Exception as exc:  # noqa: BLE001 - a metrics outage is not an outage of the thing measured
                _append(self.events_log, {"ts": self.clock(), "component": "-", "action": "publish-failed", "ok": False,
                                          "detail": type(exc).__name__})
        return results

    def heal(self, results: list[Result]) -> list[dict]:
        events = []
        for r in results:
            healer = self.healers.get(r.component)
            if r.up or not healer:
                continue
            action, ok, detail = healer.attempt()
            ev = {"ts": self.clock(), "component": r.component, "action": action, "ok": ok, "detail": detail, "was": r.detail}
            _append(self.events_log, ev)
            events.append(ev)
        return events

    def run(self, interval_s: float, stop, heal: bool = False, sleep=time.sleep, on_check=None) -> None:
        while not stop():
            results = self.check()
            if heal:
                self.heal(results)
            if on_check:
                on_check(results)
            sleep(interval_s)


class CloudWatchPublisher:
    """ComponentUp (1/0) per component. Real AWS and LocalStack take the same call."""

    def __init__(self, client, namespace: str = NAMESPACE):
        self.client, self.namespace = client, namespace

    def publish(self, results: list[Result]) -> None:
        self.client.put_metric_data(Namespace=self.namespace, MetricData=[
            {"MetricName": "ComponentUp", "Dimensions": [{"Name": "Component", "Value": r.component}],
             "Value": 1.0 if r.up else 0.0, "Unit": "Count"} for r in results])
