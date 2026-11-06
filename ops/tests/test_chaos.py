from aegis_ops import chaos
from aegis_ops.chaos import BaseEnv, Config


class FakeEnv(BaseEnv):
    """A virtual world with a virtual clock. Knobs say which failure modes it has."""

    def __init__(self, *, resume=True, restart_works=True, reask=True, contain=True, up_at_start=True):
        self.t, self.resume, self.restart_works, self.reask, self.contain = 0.0, resume, restart_works, reask, contain
        self.state = {"detector": up_at_start, "responder": up_at_start}
        self.reqs, self.log, self.n = set(), [], 0

    def now(self): return self.t
    def sleep(self, s): self.t += s
    def up(self, n): return self.state[n]

    def kill(self, n):
        self.state[n] = False; self.log.append(("kill", n))      # a dead responder leaves its request file behind
    def restart(self, n):
        self.log.append(("restart", n))
        if self.restart_works:
            self.state[n] = True
            if n == "responder" and self.resume and self.reask:
                self.n += 1
                self.reqs = {("r", self.n)}                      # the file is rewritten: a NEW request
        return self.restart_works
    def start_note(self, n): return "RESUMED" if self.resume else "from now"

    def attack_during_outage(self): return "gap"
    def score_gap(self, label): return (self.resume, 11.0 if self.resume else None)
    def provoke_leaked_key(self): self.n += 1; self.reqs = {("r", self.n)}
    def pending_ids(self): return set(self.reqs)
    def approve_pending(self): self.reqs = set(); self.log.append(("approve",))
    def key_contained(self): return self.contain and ("approve",) in self.log
    def reset_range(self): self.log.append(("reset",))


CFG = dict(settle_s=1.0, hold_s=1.0)


def test_detector_kill_survives_with_resume():
    r = chaos.run("detector-kill", FakeEnv(resume=True), Config(resume=True, **CFG))
    assert r["verdict"] == chaos.SURVIVED and r["gap_event_detected"] and r["restart_ok"] and r["recovered_s"] is not None


def test_detector_kill_without_resume_loses_the_event():
    r = chaos.run("detector-kill", FakeEnv(resume=False), Config(resume=False, **CFG))
    assert r["verdict"] == chaos.LOST and r["gap_event_detected"] is False and "blind spot" in r["notes"]


def test_detector_that_never_returns():
    r = chaos.run("detector-kill", FakeEnv(restart_works=False), Config(recover_timeout_s=5, **CFG))
    assert r["verdict"] == chaos.DEAD and r["recovered_s"] is None


def test_experiments_abort_instead_of_disturbing_a_stack_that_is_not_steady():
    assert chaos.run("detector-kill", FakeEnv(up_at_start=False), Config())["verdict"] == chaos.ABORTED
    assert chaos.run("responder-kill-pending", FakeEnv(up_at_start=False), Config())["verdict"] == chaos.ABORTED


def test_responder_kill_survives_with_recovery_and_cleans_up():
    env = FakeEnv(resume=True)
    r = chaos.run("responder-kill-pending", env, Config(resume=True))
    assert r["verdict"] == chaos.SURVIVED and r["asked_again_s"] is not None and ("reset",) in env.log


def test_responder_kill_without_recovery_drops_the_incident():
    env = FakeEnv(resume=False)
    r = chaos.run("responder-kill-pending", env, Config(resume=False))
    assert r["verdict"] == chaos.LOST and "dropped" in r["notes"] and ("reset",) in env.log


def test_asked_again_but_not_contained_is_still_a_loss():
    r = chaos.run("responder-kill-pending", FakeEnv(contain=False), Config(contain_timeout_s=3))
    assert r["verdict"] == chaos.LOST


def test_wait_returns_none_on_timeout_and_elapsed_otherwise():
    env = FakeEnv()
    assert env.wait(lambda: False, 3) is None
    env.t = 10.0
    ticks = iter([False, False, True])
    assert env.wait(lambda: next(ticks), 10, poll_s=1) == 2.0


def test_markdown_report_has_one_row_per_experiment():
    rs = [chaos.run("detector-kill", FakeEnv(), Config(**CFG)), chaos.run("responder-kill-pending", FakeEnv(), Config())]
    md = chaos.render_markdown("t", rs)
    assert md.count("| detector-kill") == 1 and md.count("| responder-kill-pending") == 1 and "SURVIVED" in md


def test_a_stale_request_file_is_not_a_re_ask():
    """The dead responder's request file is still on disk after the kill. Without recovery nothing writes a new one,
    so the verdict must be LOST even though 'something is pending'."""
    env = FakeEnv(resume=False)
    r = chaos.run("responder-kill-pending", env, Config(resume=False))
    assert r["verdict"] == chaos.LOST and r["asked_again_s"] is None


def test_detector_is_held_down_after_the_attack_before_it_is_restarted():
    env = FakeEnv(resume=True)
    seen = {}
    real_restart = env.restart
    def restart(n):
        seen["t"] = env.now()
        return real_restart(n)
    env.restart = restart
    r = chaos.run("detector-kill", env, Config(resume=True, settle_s=1.0, hold_s=45.0))
    assert seen["t"] >= 45.0 and r["detector_start"] == "RESUMED"
