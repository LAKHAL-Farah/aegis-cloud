"""Offline evidence for Stage 6 (docs/stage6-predictions.md items 1 to 5): both twins are built through moto from the same
policy documents as the Terraform, collected with the real collector, scanned, and least-privilege policies are generated.
This is moto, not LocalStack: the live run is `make sentinel-scan`."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "sentinel"), str(ROOT / "sentinel" / "tests")]
import os  # noqa: E402

for k, v in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"), ("AWS_DEFAULT_REGION", "us-east-1")):
    os.environ.setdefault(k, v)

from aegis_sentinel import leastpriv  # noqa: E402
from aegis_sentinel.actions import Universe  # noqa: E402
from aegis_sentinel.escalation import scan  # noqa: E402
from twins import ACCT, collect_twin  # noqa: E402

RUN = lambda who, name, src, **req: {  # noqa: E731
    "eventTime": "2026-11-05T10:00:00Z", "eventSource": f"{src}.amazonaws.com", "eventName": name, "awsRegion": "us-east-1",
    "requestParameters": req or None, "recipientAccountId": ACCT,
    "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCT}:user/{who}", "accountId": ACCT}}
TRAIL = [RUN("dev-svc", "ListBuckets", "s3"), RUN("dev-svc", "GetObject", "s3", bucketName="data"), RUN("dev-svc", "PutObject", "s3", bucketName="data"),
         RUN("dev-svc", "GetCallerIdentity", "sts"), RUN("dev-svc", "CreateAccessKey", "iam", userName="backdoor"),
         RUN("dev-svc", "StopLogging", "cloudtrail", trailName="t"), RUN("intern", "ListBuckets", "s3")]


def main(write: bool = False) -> int:
    out = ["# Stage 6 offline evidence: IAM Sentinel on both twins (moto, not LocalStack)", "",
           "Built through real boto3 calls from the same policy documents as `cloudpurple/terraform/modules/range-target` and",
           "`terraform/modules/iam-baseline`, then read back with the real collector. The live run is `make sentinel-scan`.", ""]
    summary = {}
    for label, hardened in (("purple twin (no boundary)", False), ("hardened twin (permission boundary)", True)):
        snap = collect_twin(hardened)
        r = scan(snap)
        summary[label] = r["summary"]
        s = r["summary"]
        out += [f"## {label}", "", f"{s['escalates']} escalate, {s['admin']} standing admin, {s['expected_admin']} expected admin, "
                f"{s['capped']} capped, {s['ordinary']} ordinary; {len(r['unresolved'])} unresolved policies.", ""]
        for p in sorted(r["principals"].values(), key=lambda x: x["name"]):
            route = " -> ".join([p["name"]] + [st["to"] for st in p["path"]]) if p["path"] else p["name"]
            out.append(f"* `{p['name']}` ({p['kind']}): **{p['category']}**" + (f", {route}, via {', '.join(st['technique'] for st in p['path'])}" if p["path"] else ""))
        out.append("")
    snap = collect_twin(False)
    t0 = time.time()
    uni = Universe()
    uni.everything()
    load_s = time.time() - t0
    usage = leastpriv.usage_from_cloudtrail(TRAIL, snap)
    out += ["## Least privilege from the purple twin's observed calls", "",
            f"Action universe: {len(uni.everything())} actions from botocore operation names ({len(uni.prefixes())} services, loaded in {load_s:.1f} s). "
            "An approximation of the IAM action list: it sizes a wildcard, it does not authorise anything.", "",
            "| Principal | Granted before | Allowed after | Fewer | Coverage of observed calls | Escalation before -> after |", "| --- | --- | --- | --- | --- | --- |"]
    note = ""
    for u in sorted(usage.values(), key=lambda x: x.name):
        r = leastpriv.analyse(snap, u, uni)
        out.append(f"| {u.name} | {r['granted_before']} | {r['granted_after']} | {r['reduction_pct']}% | "
                   f"{'complete' if r['coverage']['complete'] else 'MISSING'} ({r['coverage']['checked']} checked) | {r['category_before']} -> {r['category_after']} |")
        if u.name == "dev-svc":
            n = r["notes"]
            note = f"`dev-svc` left out as sensitive: {', '.join(n['sensitive_left_out'])}; needs no permission: {', '.join(n['no_permission_needed'])}."
    out += ["", note, "", "The reduction for a wildcard is dominated by `*` expanding to the whole universe: it says the wildcard was the problem,",
            "not that the generator is clever. The `intern` figure (4 granted, 1 needed) is the honest one.", ""]
    text = "\n".join(out)
    print(text)
    if write:
        d = ROOT / "docs" / "evidence"
        d.mkdir(parents=True, exist_ok=True)
        (d / "sentinel-offline.md").write_text(text)
        (d / "sentinel-offline.json").write_text(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main("--write" in sys.argv))
