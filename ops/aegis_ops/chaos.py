"""Chaos experiments: break one thing on purpose, with a written hypothesis, and measure what happens.

An experiment is a function of an Env (the world it can poke), so the logic is unit-tested with a fake world and
the live world (LiveEnv) only supplies hands. Every result says what was observed, never whether it was "good":
the verdict words are SURVIVED, EVENT LOST, DID NOT RECOVER, ABORTED, and the predictions file says which one was
expected (docs/stage5-predictions.md).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

SURVIVED, LOST, DEAD, ABORTED = "SURVIVED", "EVENT LOST", "DID NOT RECOVER", "ABORTED"


@dataclass
class Config:
    detect_timeout_s: float = 60.0      # how long to wait for a probe to notice the kill
    recover_timeout_s: float = 60.0
    settle_s: float = 30.0              # time for the resumed detector to read the backlog (log delivery lags ~14 s)
    hold_s: float = 45.0                # keep the detector DOWN this long after the attack, so its CloudTrail files are
                                        # delivered before it returns; otherwise a fast restart catches them without any fix
    pending_timeout_s: float = 90.0
    reask_timeout_s: float = 30.0
    contain_timeout_s: float = 30.0
    resume: bool = True                 # recorded in the result; the Env is what actually applies it


@dataclass
class Experiment:
    id: str
    title: str
    hypothesis: str
    run: object = field(repr=False)


class BaseEnv:
    """now/sleep/wait are shared; subclasses supply the hands."""

    def now(self) -> float:
        return time.time()

    def sleep(self, s: float) -> None:
        time.sleep(s)

    def wait(self, cond, timeout_s: float, poll_s: float = 0.5):
        """Seconds until cond() is true, or None on timeout."""
        start = self.now()
        while self.now() - start < timeout_s:
            if cond():
                return self.now() - start
            self.sleep(poll_s)
        return None


def _base(exp: Experiment, cfg: Config) -> dict:
    return {"experiment": exp.id, "title": exp.title, "hypothesis": exp.hypothesis, "resume": cfg.resume}


# ------------------------------------------------------------------ experiment 1
def detector_kill(env, cfg: Config) -> dict:
    exp = EXPERIMENTS["detector-kill"]
    out = _base(exp, cfg)
    if not env.up("detector"):
        return {**out, "verdict": ABORTED, "notes": "detector was not up at the start: no steady state to disturb"}
    env.kill("detector")
    noticed = env.wait(lambda: not env.up("detector"), cfg.detect_timeout_s)
    gap = env.attack_during_outage()
    env.sleep(cfg.hold_s)                     # the attack's log files must be delivered while the detector is still down
    t_restart = env.now()
    healed = env.restart("detector")
    recovered = env.wait(lambda: env.up("detector"), cfg.recover_timeout_s)
    out.update(outage_noticed_s=None if noticed is None else round(noticed, 2), restart_ok=bool(healed),
               recovered_s=None if recovered is None else round(env.now() - t_restart, 2),
               detector_start=env.start_note("detector"))
    if recovered is None:
        return {**out, "verdict": DEAD, "notes": "the detector never came back inside the timeout"}
    env.sleep(cfg.settle_s)
    caught, mttd = env.score_gap(gap)
    out.update(gap_event_detected=caught, gap_mttd_s=mttd)
    return {**out, "verdict": SURVIVED if caught else LOST,
            "notes": ("the attack made while the detector was down was detected after recovery" if caught else
                      "the attack made while the detector was down was never detected: the outage window is a blind spot")}


# ------------------------------------------------------------------ experiment 2
def responder_kill_pending(env, cfg: Config) -> dict:
    exp = EXPERIMENTS["responder-kill-pending"]
    out = _base(exp, cfg)
    if not (env.up("detector") and env.up("responder")):
        return {**out, "verdict": ABORTED, "notes": "detector and responder must both be up at the start"}
    env.provoke_leaked_key()
    asked = env.wait(lambda: bool(env.pending_ids()), cfg.pending_timeout_s)
    if asked is None:
        env.reset_range()
        return {**out, "verdict": ABORTED, "notes": "no approval was requested, so there was nothing to interrupt"}
    before = env.pending_ids()                # the dead responder's request file stays on disk: it is not a new question
    env.kill("responder")
    noticed = env.wait(lambda: not env.up("responder"), cfg.detect_timeout_s)
    t_restart = env.now()
    healed = env.restart("responder")
    recovered = env.wait(lambda: env.up("responder"), cfg.recover_timeout_s)
    out.update(outage_noticed_s=None if noticed is None else round(noticed, 2), restart_ok=bool(healed),
               recovered_s=None if recovered is None else round(env.now() - t_restart, 2),
               responder_start=env.start_note("responder"))
    if recovered is None:
        env.reset_range()
        return {**out, "verdict": DEAD, "notes": "the responder never came back inside the timeout"}
    reasked = env.wait(lambda: bool(env.pending_ids() - before), cfg.reask_timeout_s)   # a NEW request, not the stale file
    out["asked_again_s"] = None if reasked is None else round(reasked, 2)
    if reasked is None:
        env.reset_range()
        return {**out, "verdict": LOST, "notes": "after the restart nobody was asked again: the incident was silently dropped"}
    env.approve_pending()
    contained = env.wait(env.key_contained, cfg.contain_timeout_s)
    out["contained_after_approval_s"] = None if contained is None else round(contained, 2)
    env.reset_range()
    if contained is None:
        return {**out, "verdict": LOST, "notes": "asked again and approved, but the key was not contained"}
    return {**out, "verdict": SURVIVED, "notes": "interrupted mid-approval, asked again after restart, contained and verified"}


EXPERIMENTS = {
    "detector-kill": Experiment(
        "detector-kill", "Kill the detector, attack while it is down, restart it",
        "A killed detector is noticed within one heartbeat limit and restarted by the watchdog. With a checkpoint "
        "it reads the log files delivered while it was down, so the attack made during the outage is still detected. "
        "Without one it starts 'from now' and that attack is never seen.", detector_kill),
    "responder-kill-pending": Experiment(
        "responder-kill-pending", "Kill the responder while a person is deciding",
        "A responder killed with an approval pending must, after restart, ask again and contain the incident. "
        "Without recovery the ledger's claim makes the finding look 'already handled' and it is dropped.",
        responder_kill_pending),
}


def run(exp_id: str, env, cfg: Config) -> dict:
    result = EXPERIMENTS[exp_id].run(env, cfg)
    result["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(env.now()))
    return result


def render_markdown(label: str, results: list[dict]) -> str:
    lines = [f"# Chaos run {label}", "", "| Experiment | Resume | Outage noticed | Restart to up | Verdict | What happened |",
             "| --- | --- | --- | --- | --- | --- |"]
    f = lambda v: "-" if v is None else f"{v:.1f} s"  # noqa: E731
    for r in results:
        lines.append(f"| {r['experiment']} | {'on' if r['resume'] else 'off'} | {f(r.get('outage_noticed_s'))} | "
                     f"{f(r.get('recovered_s'))} | **{r['verdict']}** | {r['notes']} |")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ the live world
class LiveEnv(BaseEnv):
    """Hands for a real run: LocalStack up, `make range-up` done, no other detector or responder running.
    Not unit-tested (it needs the whole range); the logic above is."""

    GAP_SCENARIO, KEY_SCENARIO = "S01", "S11"          # harness may know scenario ids (ADR-0013 binds the product code)

    def __init__(self, stack, label: str, endpoint: str):
        self.stack, self.label, self.endpoint, self.root = stack, label, endpoint, stack.root
        sys.path[:0] = [str(self.root / "response"), str(self.root / "response" / "tools")]
        self._range = None
        from aegis_ops.watchdog import Watchdog
        self.watchdog = Watchdog(stack.probes(), stack.ops, healers=stack.healers())

    # -- process control
    def up(self, name: str) -> bool:
        return self.stack.probe(name).check().up

    def kill(self, name: str) -> None:
        self.stack.kill(name)

    def restart(self, name: str) -> bool:
        """Through the watchdog's own heal path (with its restart budget), as production would."""
        events = self.watchdog.heal(self.watchdog.check())
        return any(e["component"] == name and e["ok"] for e in events)

    # -- attacks
    def _attack(self, scenario: str, label: str) -> None:
        subprocess.run([sys.executable, str(self.root / "cloudpurple" / "run_attacks.py"), "--only", scenario,
                        "--settle", "0", "--label", label], cwd=self.root, check=False,
                       env={**os.environ, "LOCALSTACK_ENDPOINT": self.endpoint}, stdout=subprocess.DEVNULL)

    def attack_during_outage(self) -> str:
        label = f"{self.label}-gap"
        self._attack(self.GAP_SCENARIO, label)
        return label

    def score_gap(self, label: str):
        after = f"{label}-after"
        subprocess.run([sys.executable, str(self.root / "cloudpurple" / "run_attacks.py"), "--rescore", label, "--label", after],
                       cwd=self.root, check=False, stdout=subprocess.DEVNULL)
        try:
            data = json.loads((self.root / "docs" / "evidence" / "scorecards" / f"{after}.json").read_text())
            row = data["rows"][0]
            return bool(row.get("detected")), row.get("mttd")
        except (OSError, ValueError, KeyError, IndexError):
            return False, None

    # -- responder side
    def provoke_leaked_key(self) -> None:
        self._attack(self.KEY_SCENARIO, f"{self.label}-key")

    def pending_ids(self) -> set:
        """(request file, modification time): a re-asked question is a file with a NEW mtime, not just a file."""
        d = self.stack.response_state / "approvals"
        return {(p.name, p.stat().st_mtime_ns) for p in d.glob("*.request.json")} if d.exists() else set()

    def start_note(self, name: str) -> str | None:
        """The component's own account of how it started (the detector says RESUMED or 'from now'), from its log."""
        try:
            lines = (self.stack.ops / f"{name}.log").read_text(errors="replace").splitlines()
        except OSError:
            return None
        marks = [ln.strip() for ln in lines if "RESUMED" in ln or "from now" in ln or "replaying" in ln]
        return marks[-1][-160:] if marks else None

    def approve_pending(self) -> None:
        from aegis_respond.approval import FileApprover
        d = self.stack.response_state / "approvals"
        for p in FileApprover.pending(d):
            FileApprover.decide(d, p["incident_id"], True, "chaos-harness")

    def _rng(self):
        if self._range is None:
            from measure import Range          # response/tools/measure.py
            targets = json.loads((self.root / "build" / "range" / "targets.json").read_text())
            self._range = Range(targets["purple"], self.endpoint)
        return self._range

    def key_contained(self) -> bool:
        return self._rng().key_is_inactive()

    def reset_range(self) -> None:
        self._rng().reset()
