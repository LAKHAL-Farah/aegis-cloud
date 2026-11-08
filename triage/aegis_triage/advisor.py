"""The hook the responder calls (Responder(advisor=...)). It must be fast, read-only and unable to block an incident."""
from __future__ import annotations

from pathlib import Path

from . import explain as explain_mod
from .graph import Ctx, build, triage


def make_advisor(policy, playbooks, findings_dir=None, scan_path=None, explainer=None, env=None):
    fallback = ""
    if explainer is None:
        explainer, fallback = explain_mod.build(env)
    ctx = Ctx(policy, playbooks, explainer, findings_dir, Path(scan_path) if scan_path else None)
    runner = build(ctx)

    def advise(inc, plan_summary):
        return triage(inc, runner).advice_lines()

    advise.explainer_note = fallback          # why the model is not in use, if it was asked for
    advise.engine = ctx.engine
    advise.ctx = ctx
    return advise
