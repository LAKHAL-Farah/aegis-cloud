# ADR-0019: IAM Sentinel keeps its graph in memory, is read-only, and says what it does not model

* Status: accepted
* Date: 2026-11-06

## Context
Stage 6 asks for an IAM graph (the plan says Neo4j), escalation paths, and least-privilege policies generated from observed
CloudTrail usage. The lab has two IAM twins with known weaknesses (a wildcard user and a user who can rewrite their own policy),
a laptop that is already busy with Wazuh and OpenSearch, and a rule from ADR-0013: a detector must find weaknesses by what the
IAM says, not by the names in the lab.

## Decision
1. **The graph is plain Python in memory.** Principals are nodes, escalation steps are edges, the search is breadth-first. Neo4j is
   an optional export (`make sentinel-cypher` writes Cypher text; no driver is imported). The graphs involved have tens of nodes.
2. **Analysis runs on a snapshot** (`aegis.iam-snapshot/v1`, plain JSON) collected with `Get*` and `List*` calls only. The same
   snapshot gives the same result, can be diffed between runs, and needs no account in tests. A test fails if the package contains a
   call that changes IAM.
3. **A small evaluator with stated limits.** It handles Allow and Deny, `NotAction`, resource wildcards, permission boundaries
   (an allow list that intersects with the identity policies), explicit-deny-wins, trust policies, and plain SCP denies. Conditions
   are not evaluated: a conditional allow is reported as conditional, and a conditional deny never removes a path. It does not
   model session policies, resource policies, cross-account access, or most SCP behaviour.
4. **Techniques are data.** Fourteen catalogue entries (`escalation.CATALOGUE`), each with an ATT&CK id and a fix. A permission
   boundary that does not itself allow `*` caps what a principal can grant itself, so such a principal is reported as `capped`, not
   as admin.
5. **Findings are posture, not incidents.** ASFF findings go to `build/sentinel/findings/`, never `build/findings/`, so the
   responder does not try to contain a standing weakness.
6. **Least privilege is a proposal.** The generator writes a policy and never applies it. Calls that abuse a credential
   (`iam:CreateAccessKey`, `cloudtrail:StopLogging` and similar) are listed and left out unless a person passes `--keep-sensitive`. Every policy is
   checked three ways: observed calls are still allowed, the reduction is counted, and the escalation search is run again.
7. **The reduction percentage is approximate and labelled so.** The count of "actions behind a wildcard" uses botocore operation
   names as a stand-in for the IAM action list.

## Consequences
* (+) Runs in CI with moto, with no Neo4j, no LocalStack and no network.
* (+) Not tuned to the range: a test forbids lab names and scenario ids in the package.
* (-) "No path found" means "no path under these rules". A result that ignores conditions can be a false positive, and a missing
  feature can be a false negative. The report prints what it could not resolve.
* (-) The 99.98% reduction for a wildcard user mostly says that `*` is huge. The honest figure is for the narrow user (4 granted, 1 needed).
* (-) Live behaviour on LocalStack is unmeasured until `make sentinel-scan` has run (`docs/stage6-predictions.md`, item 9).
