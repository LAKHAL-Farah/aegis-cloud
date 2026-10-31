# ADR-0006: The attack range lives outside the CI gates

* Status: accepted
* Date: 2026-10-30

## Context
The vulnerable twin is, by design, everything the Stage 1 gates (Checkov, Conftest) reject: public buckets, wildcard IAM, world-open SSH.

## Decision
The range lives in `cloudpurple/`, not `terraform/live/`. The Stage 1 gates scan only `terraform/live`. The range has its own workflow (`range-ci.yml`) that checks formatting, validity, module unit tests and the scenario catalogue. A unit test asserts the Stage 1 gates never reference `cloudpurple`.

## Consequences
* (+) `main` stays green and the twin stays vulnerable, with no per-resource skips that would hide real findings.
* (+) The twin's vulnerability is itself tested (`terraform test` fails if someone "fixes" it).
* (-) A reader must understand the separation; the README and this ADR explain it.