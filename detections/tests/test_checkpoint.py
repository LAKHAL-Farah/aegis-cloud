"""Stage 5: a restarted detector resumes. These tests are the unit-level proof of ADR-0018; the live proof is the
chaos run (docs/stage5-predictions.md)."""
import json

from aegis_detect import cli
from aegis_detect.checkpoint import Checkpoint
from aegis_detect.engine import Engine
from aegis_detect.heartbeat import Heartbeat
from aegis_detect.sources import LookupSource, S3TrailSource
from helpers import ACCT, rec
from test_sources import FakeCT, FakeS3, gz

BASE = f"AWSLogs/{ACCT}/CloudTrail/us-east-1/2026/10/31/"


def test_restart_without_checkpoint_loses_the_outage_window():
    """The Stage 3 behaviour, kept as a regression marker: priming marks the backlog as read."""
    fake = FakeS3({BASE + "a.json.gz": gz([rec("ListUsers", "iam")])})
    S3TrailSource(fake, "b", ACCT).prime()
    fake.files[BASE + "during-outage.json.gz"] = gz([rec("StopLogging", "cloudtrail")])
    again = S3TrailSource(fake, "b", ACCT)
    again.prime()                       # restart "from now"
    assert again.poll() == []           # the outage event is gone for good


def test_restart_with_checkpoint_reads_the_outage_window_and_nothing_twice(tmp_path):
    fake = FakeS3({BASE + "a.json.gz": gz([rec("ListUsers", "iam")])})
    ck = Checkpoint(tmp_path / "state.json")
    src, eng = S3TrailSource(fake, "b", ACCT), Engine()
    src.prime()
    ck.save([src], eng)
    # the detector dies here; this arrives while it is down
    fake.files[BASE + "during-outage.json.gz"] = gz([rec("StopLogging", "cloudtrail")])

    src2, eng2 = S3TrailSource(fake, "b", ACCT), Engine()
    assert Checkpoint.apply(ck.load(), [src2], eng2) == 1
    events = src2.poll()
    assert [e.name for e in events] == ["StopLogging"]          # outage window read
    assert src2.poll() == []                                     # and not again
    assert any(d.event_name == "StopLogging" for d in eng2.process(events))


def test_engine_does_not_repeat_a_detection_after_restore():
    ev = [__import__("aegis_detect.model", fromlist=["Event"]).Event.from_cloudtrail(rec("StopLogging", "cloudtrail"), ACCT)]
    first = Engine()
    assert first.process(ev)
    second = Engine()
    second.restore(first.state())
    assert second.process(ev) == []


def test_lookup_cursor_round_trips():
    src = LookupSource(FakeCT(), ACCT)
    other = LookupSource(FakeCT(), ACCT)
    other.restore(src.state())
    assert other.cursor == src.cursor


def test_corrupt_or_foreign_checkpoint_is_ignored_not_fatal(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{not json")
    assert Checkpoint(p).load() is None
    p.write_text(json.dumps({"version": 99}))
    assert Checkpoint(p).load() is None
    assert Checkpoint(tmp_path / "missing.json").load() is None


def test_save_is_atomic_and_leaves_no_tmp(tmp_path):
    ck = Checkpoint(tmp_path / "state.json")
    ck.save([S3TrailSource(FakeS3({}), "b", ACCT)], Engine())
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


def test_heartbeat_follows_the_ops_contract(tmp_path):
    clock = iter([100.0, 103.0])
    hb = Heartbeat(tmp_path / "hb" / "detector.json", "detector", clock=lambda: next(clock))
    hb.beat()
    hb.beat(note="x")
    data = json.loads((tmp_path / "hb" / "detector.json").read_text())
    assert data["component"] == "detector" and data["ts"] == 103.0 and data["seq"] == 2 and isinstance(data["pid"], int)


def test_watch_resumes_end_to_end(tmp_path, monkeypatch):
    """Run the real command twice. Between the runs the process 'dies' and a trail file arrives."""
    files = {BASE + "a.json.gz": gz([rec("ListUsers", "iam")])}
    s3 = FakeS3(files)
    monkeypatch.setattr(cli, "_targets", lambda: {"purple": {"account_id": ACCT, "resources": {"trail_bucket": "b", "trail_name": "t"}}})
    monkeypatch.setattr(cli, "_client", lambda service, acct: s3 if service == "s3" else FakeCT())
    args = ["watch", "--source", "s3", "--accounts", "purple", "--once", "--state-file", str(tmp_path / "st.json"),
            "--heartbeat-file", str(tmp_path / "hb.json"), "--alert-dir", str(tmp_path / "alerts"),
            "--findings-dir", str(tmp_path / "findings")]
    assert cli.main(args) == 0                                  # first start: primes from now, saves a checkpoint
    assert not list((tmp_path / "alerts").glob("*.json"))
    files[BASE + "during-outage.json.gz"] = gz([rec("StopLogging", "cloudtrail")])
    assert cli.main(args) == 0                                  # restart: resumes
    names = [json.loads(p.read_text()) for p in (tmp_path / "alerts").glob("*.json")]
    assert names, "the event delivered during the outage must be detected after the restart"
    assert json.loads((tmp_path / "hb.json").read_text())["component"] == "detector"
