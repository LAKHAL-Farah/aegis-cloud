#!/usr/bin/env python3
"""Headline numbers, computed from the evidence files and nothing else.

  portfolio.py                 print the numbers and the CV line
  portfolio.py --write         also write docs/evidence/portfolio-numbers.{md,json}
  portfolio.py --check FILE    exit 1 if a <!--num:KEY-->value<!--/num--> marker in FILE disagrees with the evidence

Which file is the headline run for each claim is decided in docs/evidence/headline.json. A claim whose evidence file is
missing is reported as missing, never filled in."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs" / "evidence"


def _load(name: str, headline: dict):
    p = EVIDENCE / headline[name]
    return json.loads(p.read_text()) if p.is_file() else None


def numbers(evidence: Path = EVIDENCE) -> dict:
    headline = {k: v for k, v in json.loads((evidence / "headline.json").read_text()).items() if not k.startswith("_")}
    out: dict[str, str] = {}

    def put(key, value):
        out[key] = value if isinstance(value, str) else str(value)

    base, det, resp = (_load(n, headline) for n in ("baseline", "detection", "response"))
    if base and det:
        b, d = base["summary"], det["summary"]
        put("scenarios", d["total"])
        put("baseline_detected", b["detected"])
        put("baseline_prevented", b["prevented"])
        put("detected", d["detected"])
        put("scorable", d["scorable"])
        put("detected_scorable", d["detected_scorable"])
        put("excluded", ", ".join(d["excluded"]))
        put("detected_pct_of_all", f"{100 * d['detected'] / d['total']:.1f}")
        put("mttd_mean_s", f"{d['mean_mttd']:.1f}")
        put("prevented", d["prevented"])
    if resp:
        r = resp["summary"]
        put("response_pairs", r["pairs"])
        put("response_contained", r["contained"])
        put("a2c_mean_s", f"{r['mean_attack_to_contained_s']:.1f}")
        put("a2c_worst_s", f"{r['worst_attack_to_contained_s']:.1f}")
        put("machine_mean_s", f"{r['mean_machine_s']:.2f}")
        approver = resp.get("meta", {}).get("approver", "unknown")
        put("response_approval", "simulated" if approver == "auto" else f"real ({approver})")
    chaos, chaos_b = _load("chaos", headline), _load("chaos_baseline", headline)
    if chaos and chaos_b:
        put("chaos_experiments", len(chaos))
        put("chaos_baseline_lost", sum(1 for x in chaos_b if x["verdict"] == "EVENT LOST"))
        put("chaos_survived", sum(1 for x in chaos if x["verdict"] == "SURVIVED"))
    drill = _load("drill", headline)
    if drill:
        put("drill_verified", drill["verified"])
        put("drill_objects", drill["objects"])
        put("drill_rto_s", f"{drill['rto_s']:.1f}")
    slo = _load("slo", headline)
    if slo:
        put("slo_total", len(slo))
        put("slo_detection_events", slo[0]["total"])
        put("slo_ok", sum(1 for s in slo if s["status"] == "OK"))
        put("slo_no_data", sum(1 for s in slo if s["status"] == "NO DATA"))
    sent = _load("sentinel", headline)
    if sent:
        purple = next(v for k, v in sent.items() if k.startswith("purple"))
        hard = next(v for k, v in sent.items() if k.startswith("hardened"))
        put("sentinel_purple_escalates", purple["escalates"])
        put("sentinel_purple_admin", purple["admin"])
        put("sentinel_hardened_escalates", hard["escalates"])
        put("sentinel_hardened_admin", hard["admin"])
    live = _load("sentinel_live", headline)
    if live:
        accts = live["accounts"]
        put("sentinel_live_accounts", len(accts))
        put("sentinel_live_unresolved", sum(a["unresolved"] for a in accts.values()))
        for tag, key in (("purple", "purple_account"), ("hardened", "hardened_account")):
            put(f"sentinel_live_{tag}_escalates", accts[live[key]]["escalates"])
            put(f"sentinel_live_{tag}_admin", accts[live[key]]["admin"])
        put("sentinel_live_other_unexpected_admin", sum(a["admin"] + a["escalates"] for k, a in accts.items() if k != live["purple_account"]))
    tri = _load("triage", headline)
    if tri:
        put("triage_pass", "yes" if tri["passed"] else "NO")
        put("triage_median_ms", f"{tri['median_ms']:.1f}")
    return out


def cv_line(n: dict) -> str | None:
    need = ("scenarios", "detected", "mttd_mean_s", "response_contained", "response_pairs", "baseline_detected", "response_approval")
    if any(k not in n for k in need):
        return None
    return (f"AegisCloud: Terraform-built, CIS-mapped AWS landing zone on LocalStack that is attacked on purpose "
            f"({n['scenarios']} ATT&CK-mapped scenarios), detected by a Python engine (ASFF) with Wazuh and OpenSearch alongside "
            f"({n['baseline_detected']} of {n['scenarios']} caught before detections existed, {n['detected']} of {n['scenarios']} after, "
            f"mean time to detect {n['mttd_mean_s']} s), and contained by approval-gated playbooks "
            f"({n['response_contained']} of {n['response_pairs']} contained, mean {n['a2c_mean_s']} s from attack; "
            f"the approval was {n['response_approval']} in the measured run). "
            f"Includes an IAM escalation-path analyser and a cosign signing and SBOM pipeline for its Lambda package.")


def render(n: dict) -> str:
    rows = "\n".join(f"| `{k}` | {v} |" for k, v in sorted(n.items()))
    cv = cv_line(n) or "(not enough evidence to write the CV line)"
    return (f"# Headline numbers\n\nGenerated by `make portfolio` from the evidence files named in `docs/evidence/headline.json`. "
            f"Do not edit.\n\n| Key | Value |\n| --- | --- |\n{rows}\n\n## CV line\n\n> {cv}\n")


MARK = re.compile(r"<!--num:([a-z0-9_]+)-->(.*?)<!--/num-->")


def check(text: str, n: dict) -> list[str]:
    bad = []
    for m in MARK.finditer(text):
        key, shown = m.group(1), m.group(2)
        if key not in n:
            bad.append(f"{key}: no evidence for this number (shown {shown!r})")
        elif n[key] != shown:
            bad.append(f"{key}: README says {shown!r}, evidence says {n[key]!r}")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", metavar="FILE")
    a = ap.parse_args()
    n = numbers()
    if a.check:
        bad = check(Path(a.check).read_text(), n)
        for b in bad:
            print("MISMATCH", b)
        print(f"{a.check}: {'numbers match the evidence' if not bad else str(len(bad)) + ' mismatch(es)'}")
        return 1 if bad else 0
    text = render(n)
    print(text)
    if a.write:
        (EVIDENCE / "portfolio-numbers.md").write_text(text)
        (EVIDENCE / "portfolio-numbers.json").write_text(json.dumps(n, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
