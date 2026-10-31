"""Outcome classification, verdicts and the scorecard report."""
from __future__ import annotations

SUCCEEDED, DENIED, ERROR = "SUCCEEDED", "DENIED", "ERROR"
PREVENTED, DETECTED, NEITHER = "PREVENTED", "DETECTED", "NEITHER"

DENY_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
              "UnauthorizedAccess", "AuthorizationError", "Forbidden"}


def is_denied(exc) -> bool:
    resp = getattr(exc, "response", None) or {}
    err = resp.get("Error", {})
    msg = str(err.get("Message", "")).lower()
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return (err.get("Code", "") in DENY_CODES or "explicit deny" in msg
            or "not authorized" in msg or status == 403)


def prevented_by(message: str) -> str:
    m = message.lower()
    if "service control policy" in m:
        return "SCP"
    if "permissions boundary" in m or "permission boundary" in m:
        return "permission boundary"
    if "explicit deny" in m or "no identity-based policy" in m:
        return "IAM policy"
    return "access denied (layer not named)"


def verdict(hardened_outcome: str | None, detected: bool) -> str:
    parts = []
    if hardened_outcome == DENIED:
        parts.append(PREVENTED)
    if detected:
        parts.append(DETECTED)
    return "+".join(parts) or NEITHER


def summarize(rows: list[dict]) -> dict:
    def outcome(r, side):
        return (r.get(side) or {}).get("outcome")

    mttds = [r["mttd"] for r in rows if r.get("mttd") is not None]
    return {
        "total": len(rows),
        "errored": sum(outcome(r, "purple") == ERROR for r in rows),
        "succeeded_on_purple": sum(outcome(r, "purple") == SUCCEEDED for r in rows),
        "detected": sum(bool(r.get("detected")) for r in rows),
        "prevented": sum(outcome(r, "hardened") == DENIED for r in rows),
        "neither": sum(r.get("verdict") == NEITHER for r in rows),
        "mean_mttd": (sum(mttds) / len(mttds)) if mttds else None,
    }


def _cell(side: dict | None) -> str:
    if not side:
        return "-"
    out = side["outcome"]
    if out == DENIED and side.get("prevented_by"):
        return f"{out} ({side['prevented_by']})"
    return out


def headline(s: dict) -> str:
    return (f"Detected: {s['detected']} of {s['total']}  |  "
            f"Prevented on hardened twin: {s['prevented']} of {s['total']}  |  "
            f"Neither: {s['neither']}  |  Errored: {s['errored']}")


def render_markdown(label: str, stamp: str, rows: list[dict], s: dict) -> str:
    out = [f"# CloudPurple scorecard: {label}", "", f"_Generated {stamp}_", "", f"**{headline(s)}**", ""]
    if s["mean_mttd"] is not None:
        out += [f"Mean time to detect: {s['mean_mttd']:.1f} s", ""]
    out += ["| ID | ATT&CK | Scenario | Purple (vulnerable) | Hardened | Telemetry | Detected | MTTD | Verdict |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        tele = (r.get("purple") or {}).get("telemetry", "-")
        mttd = f"{r['mttd']:.1f} s" if r.get("mttd") is not None else "-"
        out.append(f"| {r['id']} | {r['technique']} | {r['name']} | {_cell(r.get('purple'))} | "
                   f"{_cell(r.get('hardened'))} | {tele} | {'yes' if r.get('detected') else 'no'} | {mttd} | {r['verdict']} |")
    out += ["", "## Notes", ""]
    for r in rows:
        for side in ("purple", "hardened"):
            d = r.get(side)
            if d and d["outcome"] in (DENIED, ERROR):
                out.append(f"* {r['id']} {side}: {d['outcome']}: {d.get('detail', '')[:200]}")
        if r.get("alert"):
            out.append(f"* {r['id']} matched alert: {r['alert']}")
    return "\n".join(out) + "\n"