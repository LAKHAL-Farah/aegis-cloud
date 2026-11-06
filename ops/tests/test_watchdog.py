import json
import os

from pathlib import Path

from aegis_ops.components import Stack
from aegis_ops.probes import DockerProbe, HeartbeatProbe, HttpProbe, Result
from aegis_ops.watchdog import CloudWatchPublisher, Healer, Watchdog


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def write_hb(path, ts, pid=None, component="detector"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"component": component, "ts": ts, "pid": pid or os.getpid(), "seq": 1}))


def test_heartbeat_probe_fresh_stale_missing_and_dead_pid(tmp_path):
    clock, p = Clock(), tmp_path / "hb.json"
    probe = HeartbeatProbe("detector", p, 10, clock=clock)
    assert probe.check().detail == "no heartbeat file"
    write_hb(p, 995)
    assert probe.check().up
    write_hb(p, 900)
    r = probe.check()
    assert not r.up and "old" in r.detail
    write_hb(p, 999, pid=99999999)
    r = probe.check()
    assert not r.up and "gone" in r.detail
    p.write_text("{garbage")
    assert not probe.check().up


def test_http_probe_up_down_and_error():
    class Resp:
        def __init__(self, status):
            self.status = status
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    assert HttpProbe("x", "u", opener=lambda url, timeout: Resp(200)).check().up
    assert not HttpProbe("x", "u", opener=lambda url, timeout: Resp(503)).check().up

    def boom(url, timeout):
        raise ConnectionRefusedError
    r = HttpProbe("x", "u", opener=boom).check()
    assert not r.up and r.detail == "ConnectionRefusedError"


def test_docker_probe():
    class Out:
        def __init__(self, rc, out):
            self.returncode, self.stdout = rc, out
    assert DockerProbe("w", "c", run=lambda *a, **k: Out(0, "true\n")).check().up
    assert not DockerProbe("w", "c", run=lambda *a, **k: Out(1, "")).check().up


def test_check_appends_one_line_per_tick_in_the_slo_format(tmp_path):
    class P:
        def __init__(self, name, up):
            self.name, self.up = name, up
        def check(self):
            return Result(self.name, self.up, "d")
    wd = Watchdog([P("a", True), P("b", False)], tmp_path, clock=Clock())
    wd.check(); wd.check()
    lines = [json.loads(x) for x in (tmp_path / "health.jsonl").read_text().splitlines()]
    assert len(lines) == 2 and lines[0]["components"]["b"] == {"up": False, "detail": "d"} and lines[0]["ts"] == 1000.0


def test_heal_restarts_only_what_is_down_and_records_it(tmp_path):
    calls = []
    class P:
        def __init__(self, name, up):
            self.name, self.up = name, up
        def check(self):
            return Result(self.name, self.up, "stale")
    healers = {"a": Healer("a", lambda: calls.append("a") or True), "b": Healer("b", lambda: calls.append("b") or True)}
    wd = Watchdog([P("a", False), P("b", True), P("c", False)], tmp_path, healers=healers, clock=Clock())
    events = wd.heal(wd.check())
    assert calls == ["a"] and events[0]["action"] == "restart" and events[0]["ok"] and events[0]["was"] == "stale"
    assert json.loads((tmp_path / "events.jsonl").read_text().splitlines()[0])["component"] == "a"


def test_healer_gives_up_after_the_budget_and_recovers_after_the_window():
    clock = Clock(0.0)
    h = Healer("d", lambda: True, max_restarts=2, window_s=100, clock=clock)
    assert h.attempt()[0] == "restart" and h.attempt()[0] == "restart"
    action, ok, detail = h.attempt()
    assert action == "gave-up" and not ok and "needs a person" in detail
    clock.t = 150.0
    assert h.attempt()[0] == "restart"


def test_a_crashing_restart_is_recorded_not_raised():
    def boom():
        raise RuntimeError("no make")
    action, ok, detail = Healer("d", boom).attempt()
    assert action == "restart" and not ok and "RuntimeError" in detail


def test_publisher_failure_never_breaks_the_check(tmp_path):
    class Bad:
        def publish(self, results):
            raise ConnectionError
    class P:
        component = "a"
        def check(self):
            return Result("a", True, "")
    wd = Watchdog([P()], tmp_path, publisher=Bad(), clock=Clock())
    assert wd.check()[0].up
    assert json.loads((tmp_path / "events.jsonl").read_text())["action"] == "publish-failed"


def test_cloudwatch_publisher_sends_componentup_per_component():
    sent = []
    class CW:
        def put_metric_data(self, **kw):
            sent.append(kw)
    CloudWatchPublisher(CW()).publish([Result("detector", True, ""), Result("responder", False, "")])
    data = sent[0]["MetricData"]
    assert sent[0]["Namespace"] == "Aegis/Pipeline"
    assert {(d["Dimensions"][0]["Value"], d["Value"]) for d in data} == {("detector", 1.0), ("responder", 0.0)}


def test_stack_commands(tmp_path):
    on = Stack(tmp_path, resume=True, python="py")
    off = Stack(tmp_path, resume=False, python="py")
    det_on, det_off = on.command("detector"), off.command("detector")
    assert "--state-file" in det_on and "--state-file" not in det_off and "--heartbeat-file" in det_off
    rsp_on, rsp_off = on.command("responder"), off.command("responder")
    assert "--resume" in rsp_on and "--resume" not in rsp_off and "--execute" in rsp_off and "--approver" in rsp_off
    assert [p.component for p in on.probes()] == ["localstack", "detector", "responder"]
    assert Stack(tmp_path, opensearch="http://x:9200").probes()[-1].component == "opensearch"


def test_stack_start_waits_for_a_fresh_heartbeat(tmp_path):
    spawned = []
    t = {"now": 0.0}
    def popen(cmd, **kw):
        spawned.append(cmd)
        write_hb(tmp_path / "build" / "ops" / "heartbeats" / "detector.json", t["now"] + 1)   # the child's first beat
    s = Stack(tmp_path, python="py", popen=popen, clock=lambda: t["now"],
              sleep=lambda x: t.__setitem__("now", t["now"] + x))
    s.probe = lambda name: HeartbeatProbe(name, tmp_path / "build" / "ops" / "heartbeats" / f"{name}.json", 20,
                                          clock=lambda: t["now"])
    assert s.start("detector") and len(spawned) == 1
    assert not Stack(tmp_path, python="py", popen=lambda *a, **k: None, clock=lambda: t["now"],
                     sleep=lambda x: t.__setitem__("now", t["now"] + x)).start("responder", timeout_s=2)


def test_fresh_state_deletes_the_checkpoint_and_archives_the_responder_state(tmp_path):
    s = Stack(tmp_path)
    assert s.fresh_state("t0") is None                                   # nothing there yet: fine
    (s.ops).mkdir(parents=True)
    (s.ops / "detector-state.json").write_text("{}")
    (s.response_state / "approvals").mkdir(parents=True)
    (s.response_state / "ledger.json").write_text("{}")
    dest = s.fresh_state("t1")
    assert not (s.ops / "detector-state.json").exists() and not s.response_state.exists()
    assert (dest / "ledger.json").exists()                               # kept as evidence


def test_no_healing_while_a_person_has_the_stack_stopped(tmp_path):
    calls = []
    class P:
        component = "a"
        def check(self):
            return Result("a", False, "gone")
    wd = Watchdog([P()], tmp_path, healers={"a": Healer("a", lambda: calls.append(1) or True)}, clock=Clock(),
                  maintenance=lambda: True)
    assert wd.heal(wd.check()) == [] and calls == []


def test_a_killed_child_that_nobody_reaped_is_not_alive():
    """The zombie case measured on the live run: os.kill(pid, 0) says alive, the process is dead."""
    import signal, subprocess, time
    from aegis_ops.probes import pid_alive
    child = subprocess.Popen(["sleep", "60"])
    assert pid_alive(child.pid)
    os.kill(child.pid, signal.SIGKILL)
    time.sleep(0.3)
    assert not pid_alive(child.pid)          # a zombie until child.wait()
    child.wait()
    assert not pid_alive(child.pid)


def test_gave_up_is_announced_once_per_episode(tmp_path):
    clock = Clock(0.0)
    h = Healer("d", lambda: True, max_restarts=1, window_s=1000, clock=clock)
    class Down:
        component = "d"
        def check(self): return Result("d", False, "gone")
    class Up:
        component = "d"
        def check(self): return Result("d", True, "ok")
    wd = Watchdog([Down()], tmp_path, healers={"d": h}, clock=clock)
    first = wd.heal(wd.check())              # restart
    spam = [wd.heal(wd.check()) for _ in range(5)]
    actions = [e["action"] for e in first + [x for batch in spam for x in batch]]
    assert actions == ["restart", "gave-up"]                       # one announcement, not five
    wd.probes = [Up()]
    wd.heal(wd.check())                                            # recovered: the episode is over
    assert h.announced is False


def test_stale_or_foreign_pid_files_do_not_count_as_a_running_watchdog(tmp_path):
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location("ops_cli", Path(__file__).resolve().parents[1] / "ops.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pf = tmp_path / "watchdog.pid"
    assert mod.watchdog_running(pf) is None                       # no file
    pf.write_text("not a number")
    assert mod.watchdog_running(pf) is None
    pf.write_text("99999999")
    assert mod.watchdog_running(pf) is None                       # no such process
    pf.write_text(str(os.getpid()))
    assert mod.watchdog_running(pf) is None                       # alive, but it is pytest, not a watchdog
