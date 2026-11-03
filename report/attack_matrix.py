#!/usr/bin/env python3
"""Before/after scorecards -> docs/evidence/attack-matrix.md and .html (the Stage 3 demo artefact).

Usage: python3 report/attack_matrix.py --before baseline --after stage3-v1"""
from __future__ import annotations

import argparse
import html
import json
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CARDS = ROOT / "docs" / "evidence" / "scorecards"
TACTIC_ORDER = ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
                "Discovery", "Collection", "Exfiltration", "Impact"]


def load(label: str) -> dict:
    return json.loads((CARDS / f"{label}.json").read_text())


def load_known_limits() -> dict:
    """docs/known-limits.json: {"S08": "why this miss is a LocalStack limitation"}. Written by a human, with evidence."""
    path = ROOT / "docs" / "known-limits.json"
    return json.loads(path.read_text()) if path.exists() else {}


def miss_reason(row: dict, known: dict | None = None) -> str:
    if known and row.get("id") in known:
        return "known limitation: " + known[row["id"]]
    """A first, mechanical explanation for a miss. A human still has to confirm it (docs/STAGE3.md section 8)."""
    tele = ((row.get("purple") or {}).get("telemetry") or "-").split(" ")[0]
    if (row.get("purple") or {}).get("outcome") != "SUCCEEDED":
        return "the attack did not succeed on purple"
    if tele == "NONE":
        return "no telemetry: LocalStack did not record the event"
    if tele == "PARTIAL":
        return "partial telemetry: some expected events were not recorded"
    if tele == "DATA-EVENT":
        return "needs S3 data events: check the telemetry probe"
    return "event recorded but no rule fired (or it fired late): investigate"


def fmt_mttd(v) -> str:
    return "-" if v is None else f"{v:.1f} s"


def build(before: dict, after: dict, known: dict | None = None) -> tuple[str, str]:
    b_rows, a_rows = {r["id"]: r for r in before["rows"]}, {r["id"]: r for r in after["rows"]}
    bs, as_ = before["summary"], after["summary"]
    md = [f"# ATT&CK coverage: {before['label']} to {after['label']}", "",
          f"| | {before['label']} | {after['label']} |", "| --- | --- | --- |",
          f"| Detected | {bs['detected']} of {bs['total']} | **{as_['detected']} of {as_['total']}** |",
          f"| Prevented on hardened twin | {bs['prevented']} of {bs['total']} | {as_['prevented']} of {as_['total']} |",
          f"| Mean time to detect | {fmt_mttd(bs.get('mean_mttd'))} | {fmt_mttd(as_.get('mean_mttd'))} |",
          f"| Other alerts during the run | - | {as_.get('other_alerts', 0)} |", "",
          "## Per scenario", "",
          "| ID | ATT&CK | Scenario | Before | After | MTTD | Detected by | Why missed |",
          "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for sid, a in a_rows.items():
        b = b_rows.get(sid, {})
        by = f"{a.get('alert_rule')} ({a.get('alert_source')})" if a.get("detected") else "-"
        why = "-" if a.get("detected") else miss_reason(a, known)
        md.append(f"| {sid} | {a['technique']} | {a['name']} | {'detected' if b.get('detected') else 'missed'} | "
                  f"**{'detected' if a.get('detected') else 'MISSED'}** | {fmt_mttd(a.get('mttd'))} | {by} | {why} |")

    grid: "OrderedDict[str, list]" = OrderedDict((t, []) for t in TACTIC_ORDER)
    for a in a_rows.values():
        grid.setdefault(a["tactic"], []).append(a)
    md += ["", "## Matrix (tactic x technique)", ""]
    for tactic, items in grid.items():
        if items:
            md.append(f"* **{tactic}**: " + ", ".join(
                f"{i['technique']} {'OK' if i.get('detected') else 'MISS'}" for i in items))

    cells = []
    for tactic, items in grid.items():
        if not items:
            continue
        col = "".join(
            f'<div class="cell {"ok" if i.get("detected") else "miss"}"><b>{html.escape(i["technique"])}</b>'
            f'<span>{html.escape(i["id"])} {html.escape(i["name"])}</span>'
            f'<small>{"MTTD " + fmt_mttd(i.get("mttd")) if i.get("detected") else html.escape(miss_reason(i, known))}</small></div>'
            for i in items)
        cells.append(f'<div class="col"><h2>{html.escape(tactic)}</h2>{col}</div>')
    page = f"""<!doctype html><meta charset="utf-8"><title>AegisCloud ATT&amp;CK coverage</title>
<style>
:root{{--bg:#fff;--fg:#1a1a1a;--ok:#d7f0dd;--okb:#2e7d46;--miss:#fbdcdc;--missb:#b3261e}}
@media(prefers-color-scheme:dark){{:root{{--bg:#16181b;--fg:#e8e8e8;--ok:#173d24;--okb:#5fcf80;--miss:#4a1d1d;--missb:#ff8a80}}}}
body{{font:14px system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:24px}}
.grid{{display:flex;gap:12px;overflow-x:auto}}.col{{min-width:190px}}h1{{font-size:20px}}h2{{font-size:13px;text-transform:uppercase;opacity:.7}}
.cell{{border-left:4px solid;padding:8px;margin-bottom:8px;border-radius:4px}}.ok{{background:var(--ok);border-color:var(--okb)}}
.miss{{background:var(--miss);border-color:var(--missb)}}.cell span,.cell small{{display:block}}.cell small{{opacity:.75}}
</style><h1>ATT&amp;CK coverage: {html.escape(before['label'])} &rarr; {html.escape(after['label'])}:
{as_['detected']} of {as_['total']} detected</h1><div class="grid">{''.join(cells)}</div>"""
    return "\n".join(md) + "\n", page


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", default="baseline")
    ap.add_argument("--after", required=True)
    args = ap.parse_args()
    md, page = build(load(args.before), load(args.after), load_known_limits())
    out = ROOT / "docs" / "evidence"
    (out / "attack-matrix.md").write_text(md)
    (out / "attack-matrix.html").write_text(page)
    print(md)
    print(f"wrote {out}/attack-matrix.md and .html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())