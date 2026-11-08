"""The triage graph: parse -> enrich -> assess -> propose -> explain -> guard -> finish.

It runs on LangGraph when that is installed and on a tiny sequential runner otherwise. The nodes are the same plain
functions either way, so the CI tests need no extra dependency (ADR-0020)."""
from __future__ import annotations

import os
from typing import Any, Callable, TypedDict

from . import assess as assess_mod
from . import facts as facts_mod
from . import text
from .explain import ExplainerError, TemplateExplainer
from .note import ACTIONS, PRIORITIES, TriageNote


class State(TypedDict, total=False):
    incident: Any
    facts: dict
    assessment: dict
    proposal: dict
    explanation: dict
    explainer: str
    note: TriageNote


class Ctx:
    def __init__(self, policy, playbooks, explainer=None, findings_dir=None, scan_path=None, window_s=facts_mod.WINDOW_S, now=None):
        import time
        self.policy, self.playbooks = policy, playbooks
        self.explainer = explainer or TemplateExplainer()
        self.findings_dir, self.scan_path, self.window_s = findings_dir, scan_path, window_s
        self.now = now or time.time
        self.fallback = ""


def make_nodes(ctx: Ctx) -> list[tuple[str, Callable[[State], dict]]]:
    def enrich(s: State) -> dict:
        inc = s["incident"]
        pb = next((p for p in ctx.playbooks.values() if p.matches(inc, ctx.policy)), None)
        f = {"rule": inc.rule, "technique": inc.technique, "tactic": inc.tactic, "severity": inc.severity,
             "protected": ctx.policy.is_protected(inc.identity), "playbook": pb.id if pb else "",
             "related": facts_mod.related(inc, ctx.findings_dir, ctx.window_s),
             "exposure": facts_mod.exposure(inc, ctx.scan_path, ctx.now)}
        return {"facts": f}

    def assess(s: State) -> dict:
        return {"assessment": assess_mod.assess(s["facts"])}

    def propose(s: State) -> dict:
        return {"proposal": assess_mod.propose(s["facts"], s["assessment"])}

    def explain(s: State) -> dict:
        inc, f, a, p = s["incident"], s["facts"], s["assessment"], s["proposal"]
        for_model = {                                  # decided values first, then the untrusted strings, already sanitised
            "rule": inc.rule, "technique": inc.technique, "tactic": inc.tactic, "severity": inc.severity,
            "priority": a["priority"], "proposed_action": p["action"], "playbook": p["playbook"], "reasons": a["reasons"],
            "related_rules": sorted(set(f["related"])), "exposure": f["exposure"].get("category", "unknown"),
            "account_id": inc.account_id,
            "principal": text.clean(inc.identity), "resource": text.tail(inc.resource_id), "event_name": text.event_name(inc.event_name),
        }
        ctx.fallback = ""
        try:
            out, name = ctx.explainer.explain(for_model), ctx.explainer.name
        except ExplainerError as exc:
            out, name, ctx.fallback = TemplateExplainer().explain(for_model), "template", str(exc)
        s_facts = for_model
        return {"explanation": out, "explainer": name, "facts": {**f, "for_model": s_facts}}

    def guard(s: State) -> dict:
        out, name = s["explanation"], s["explainer"]
        reason = _check(out) if name != "template" else ""      # template text is built only from sanitised facts
        if reason:                                     # never show it: use the template and say why
            out = TemplateExplainer().explain(s["facts"]["for_model"])
            name, ctx.fallback = "template", f"model text rejected: {reason}"
        return {"explanation": out, "explainer": name}

    def finish(s: State) -> dict:
        inc, a, p, out = s["incident"], s["assessment"], s["proposal"], s["explanation"]
        label = s["explainer"]
        if ctx.fallback:
            label = f"template (fallback: {ctx.fallback})"
        assert p["action"] in ACTIONS and a["priority"] in PRIORITIES
        return {"note": TriageNote(
            incident=inc.short, priority=a["priority"], action=p["action"], playbook=p["playbook"], reasons=a["reasons"],
            evidence=a["evidence"], summary=out["summary"], check_next=out["check_next"], explainer=label,
            engine=getattr(ctx, "engine", "sequential"))}

    return [("enrich", enrich), ("assess", assess), ("propose", propose), ("explain", explain), ("guard", guard), ("finish", finish)]


def _check(out) -> str:
    if not isinstance(out, dict) or set(out) - {"summary", "check_next"}:
        return "unexpected shape"
    summary, nxt = out.get("summary"), out.get("check_next")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 400:
        return "summary missing or too long"
    if not isinstance(nxt, list) or len(nxt) > 3 or any(not isinstance(x, str) or not x.strip() or len(x) > 160 for x in nxt):
        return "check_next malformed"
    for item in [summary, *nxt]:
        why = text.violation(item)
        if why:
            return why
    return ""


class Sequential:
    engine = "sequential"

    def __init__(self, nodes):
        self.nodes = nodes

    def invoke(self, state: State) -> State:
        state = dict(state)
        for _, fn in self.nodes:
            state.update(fn(state))
        return state


def build(ctx: Ctx):
    nodes = make_nodes(ctx)
    runner: Any
    if os.environ.get("AEG_TRIAGE_ENGINE", "").lower() != "sequential":
        try:
            from langgraph.graph import END, START, StateGraph
            g = StateGraph(State)
            for name, fn in nodes:
                g.add_node(name, fn)
            g.add_edge(START, nodes[0][0])
            for (a, _), (b, _) in zip(nodes, nodes[1:]):
                g.add_edge(a, b)
            g.add_edge(nodes[-1][0], END)
            runner = g.compile()
            ctx.engine = "langgraph"
            return runner
        except ImportError:
            pass
    ctx.engine = "sequential"
    return Sequential(nodes)


def triage(incident, runner) -> TriageNote:
    return runner.invoke({"incident": incident})["note"]
