import sys
from pathlib import Path

import boto3
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import probe_ops as probe  # noqa: E402


def moto_client(service, account):
    return boto3.client(service, region_name="us-east-1")


def test_probes_run_against_moto_and_never_raise():
    with mock_aws():
        rows = probe.run_all(client=moto_client, probes=[p for p in probe.PROBES if "CloudTrail" not in p[0]])
    by = {n: (v, d) for n, v, d in rows}
    assert by["CloudWatch custom metrics"][0] == probe.WORKS
    assert by["S3 versioning (restore drill)"][0] == probe.WORKS
    assert by["CloudWatch alarm states"][0] == probe.STORED
    assert all(v in (probe.WORKS, probe.STORED, probe.NOPE) for _, v, _ in rows)


def test_a_crashing_probe_becomes_a_verdict():
    def boom(client, wait_s):
        raise RuntimeError("nope")
    rows = probe.run_all(client=moto_client, probes=[("x", boom)])
    assert rows[0][1] == probe.NOPE and "RuntimeError" in rows[0][2]


def test_render_is_a_markdown_table():
    md = probe.render([("a", probe.WORKS, "d")])
    assert "| a | **WORKS** | d |" in md
