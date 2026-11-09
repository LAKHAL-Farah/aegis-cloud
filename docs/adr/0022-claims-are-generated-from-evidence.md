# ADR-0022: Numbers in the README are generated from evidence files and checked

* Status: accepted
* Date: 2026-11-06

## Context
The project's risk table lists "claims that exceed reality". While drafting the Stage 7 CV line, the headline response result
turned out to come from a simulated approval, and the draft had said "human approval in Slack". A number typed by hand can drift
or overclaim without anyone noticing.

## Decision
1. `docs/evidence/headline.json` names the one evidence file that is the headline run for each claim.
2. `release/portfolio.py` computes every headline number from those files, including the words that qualify them (for example
   "simulated"), and writes `docs/evidence/portfolio-numbers.{md,json}` and the CV line.
3. The README wraps each number in `<!--num:key-->value<!--/num-->`. `make docs-check` (and CI) fails if a marked number differs
   from the evidence, or has no evidence.
4. A claim whose evidence file is missing is reported as missing, not filled in.
5. The same checks cover the architecture page (every path it names exists) and the ADR index (numbers are contiguous).

## Consequences
* (+) Changing the headline run is a one-line edit and a regeneration, and an old number cannot survive in prose.
* (-) It checks that the README matches the evidence, not that the evidence is good. A weak run is still a weak run.
* (-) Only marked numbers are checked. A number typed without the marker is not.
