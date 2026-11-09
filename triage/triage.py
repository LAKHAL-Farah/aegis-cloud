#!/usr/bin/env python3
"""Triage CLI. It reads a finding and prints the advisory note the approver would see. It changes nothing.

  triage.py note FINDING.json [--scan FILE] [--findings-dir DIR]     the note for one finding
  triage.py eval [--write]                                           offline evaluation: decisions, hostile input, bad models, timing
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for p in (HERE, ROOT / "response", ROOT / "detections"):
    sys.path.insert(0, str(p))


def cmd_note(a) -> int:
    from aegis_respond.incident import Incident
    from aegis_respond.playbooks import PLAYBOOKS
    from aegis_respond.policy import ResponsePolicy
    from aegis_triage.advisor import make_advisor
    inc = Incident.from_asff(json.loads(Path(a.finding).read_text()))
    adv = make_advisor(ResponsePolicy.load(), PLAYBOOKS, findings_dir=a.findings_dir or ROOT / "build" / "findings",
                       scan_path=a.scan or ROOT / "build" / "sentinel" / "scan.json")
    if adv.explainer_note:
        print(f"(template text only: {adv.explainer_note})")
    for line in adv(inc, []):
        print(line)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("note")
    n.add_argument("finding")
    n.add_argument("--scan")
    n.add_argument("--findings-dir")
    e = sub.add_parser("eval")
    e.add_argument("--write", action="store_true", help="save docs/evidence/triage-eval.md and .json")
    a = ap.parse_args()
    if a.cmd == "eval":
        from tools.evaluate import main as evaluate
        return evaluate(write=a.write)
    return cmd_note(a)


if __name__ == "__main__":
    sys.exit(main())
