"""Optional Neo4j export. The analysis does not need Neo4j (ADR-0019); this writes Cypher you can paste into it to look
at the same graph. No driver is imported and nothing connects anywhere."""
from __future__ import annotations

from .account import Account
from .escalation import build
from .graph import ADMIN, structural_edges


def _q(value) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def export(snap: dict) -> str:
    acct = Account(snap)
    graph, _ = build(acct)
    lines = ["// AegisCloud IAM graph. Paste into Neo4j Browser. Generated, read-only analysis output.",
             "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE;",
             f"MERGE (:Admin:Node {{id: {_q(ADMIN)}, name: 'ADMIN'}});"]
    for arn, p in sorted(acct.principals.items()):
        lines.append(f"MERGE (:{p['kind'].title()}:Node {{id: {_q(arn)}, name: {_q(p['name'])}}});")
    for arn, p in sorted(acct.policies.items()):
        lines.append(f"MERGE (:Policy:Node {{id: {_q(arn)}, name: {_q(p['name'])}}});")
    for e in structural_edges(acct) + graph.edges:
        lines.append(f"MATCH (a:Node {{id: {_q(e.src)}}}), (b:Node {{id: {_q(e.dst)}}}) "
                     f"MERGE (a)-[:{e.kind} {{technique: {_q(e.technique)}, label: {_q(e.label)}, "
                     f"conditional: {str(e.conditional).lower()}}}]->(b);")
    return "\n".join(lines) + "\n"
