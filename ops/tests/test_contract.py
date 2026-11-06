"""docs/ops-contract.md: the two heartbeat writers (detector, responder) and the reader agree."""
import json

from aegis_detect.heartbeat import Heartbeat as DetectBeat
from aegis_ops.probes import HeartbeatProbe, read_heartbeat
from aegis_respond.heartbeat import Heartbeat as RespondBeat


def test_both_writers_satisfy_the_reader(tmp_path):
    for cls, name in ((DetectBeat, "detector"), (RespondBeat, "responder")):
        path = tmp_path / f"{name}.json"
        cls(path, name).beat()
        hb = read_heartbeat(path)
        assert hb and hb["component"] == name and set(hb) >= {"component", "ts", "pid", "seq"}
        assert HeartbeatProbe(name, path, max_age_s=5).check().up


def test_the_two_copies_of_the_writer_are_identical():
    import aegis_detect.heartbeat as a, aegis_respond.heartbeat as b
    assert open(a.__file__).read() == open(b.__file__).read(), "keep response/aegis_respond/heartbeat.py a copy of the detector's"
