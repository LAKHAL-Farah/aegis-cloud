# Stage 6 targets: IAM Sentinel. Included by the main Makefile (same .RECIPEPREFIX).
SENT_DIR := sentinel
SENT_OUT := build/sentinel
# LocalStack accepts any secret; the access key is the account id. Set here so the targets work without `source scripts/env.sh`.
SENT_AWS := AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
ENDPOINT ?= http://localhost:4566
# Account ids as in scripts/env.sh and scripts/env_range.sh; the hardened twin's id is generated.
SENT_ACCOUNTS ?= 111111111111 222222222222 333333333333 444444444444 555555555555 $(shell jq -r '.hardened.account_id // empty' build/range/targets.json 2>/dev/null)

.PHONY: sentinel-install sentinel-test sentinel-test-full sentinel-collect sentinel-scan sentinel-gate sentinel-trail sentinel-leastpriv sentinel-cypher triage-test triage-eval triage-install intel-test

sentinel-install:  ## install Sentinel dependencies into the venv
> .venv/bin/pip install -r $(SENT_DIR)/requirements.txt

sentinel-test:  ## evaluator, escalation techniques, least-privilege, findings (moto, no LocalStack). Skips the test that loads every AWS service model
> $(PY) -m pytest $(SENT_DIR)/tests -q -m "not slow"

sentinel-test-full:  ## the same plus the real-action-list test (several seconds on a normal disk, much longer on a slow one)
> $(PY) -m pytest $(SENT_DIR)/tests -q

sentinel-collect:  ## read-only IAM snapshot of every account into build/sentinel/ (needs LocalStack, applied roots and the range)
> for a in $(SENT_ACCOUNTS); do $(SENT_AWS) AWS_ACCESS_KEY_ID=$$a $(PY) $(SENT_DIR)/sentinel.py collect --endpoint $(ENDPOINT) --account $$a || echo "  skipped $$a"; done

sentinel-scan: sentinel-collect  ## escalation paths and standing admins, written to build/sentinel/scan.json and posture findings
> $(PY) $(SENT_DIR)/sentinel.py scan $(SENT_OUT)/snapshot-*.json --scp policies/scp/*.json --write

sentinel-gate:  ## CI-style: exit 1 if any scanned principal escalates or is an unexpected admin (SNAP=file.json ...)
> test -n "$(SNAP)" || { echo "usage: make sentinel-gate SNAP=\"build/sentinel/snapshot-444444444444.json\""; exit 1; }
> $(PY) $(SENT_DIR)/sentinel.py scan $(SNAP) --scp policies/scp/*.json --fail-on-path

sentinel-trail:  ## recent CloudTrail events of ACCT (default: the workload account) as build/sentinel/trail.json
> $(SENT_AWS) AWS_ACCESS_KEY_ID=$(or $(ACCT),444444444444) $(PY) $(SENT_DIR)/sentinel.py trail --endpoint $(ENDPOINT)

sentinel-leastpriv:  ## policy from observed usage: make sentinel-leastpriv ACCT=555555555555 PRINCIPAL=name [KEEP=1]
> test -n "$(ACCT)" -a -n "$(PRINCIPAL)" || { echo "usage: make sentinel-leastpriv ACCT=<id> PRINCIPAL=<name>"; exit 1; }
> $(SENT_AWS) AWS_ACCESS_KEY_ID=$(ACCT) $(PY) $(SENT_DIR)/sentinel.py trail --endpoint $(ENDPOINT) --out $(SENT_OUT)/trail-$(ACCT).json
> $(PY) $(SENT_DIR)/sentinel.py leastpriv --snapshot $(SENT_OUT)/snapshot-$(ACCT).json --trail $(SENT_OUT)/trail-$(ACCT).json --principal $(PRINCIPAL) --scp policies/scp/*.json $(if $(KEEP),--keep-sensitive,)

sentinel-cypher:  ## Neo4j import script for one snapshot: make sentinel-cypher SNAP=build/sentinel/snapshot-<id>.json
> test -n "$(SNAP)" || { echo "usage: make sentinel-cypher SNAP=<snapshot.json>"; exit 1; }
> $(PY) $(SENT_DIR)/sentinel.py cypher $(SNAP) > $(SENT_OUT)/graph.cypher && echo "wrote $(SENT_OUT)/graph.cypher"

triage-install:  ## optional: LangGraph and the Anthropic SDK (the triage runs without them)
> .venv/bin/pip install -r triage/requirements-llm.txt

triage-test:  ## triage decisions, hostile input, misbehaving model, cannot-act checks (no network, no model)
> $(PY) -m pytest triage/tests -q

triage-eval:  ## offline evaluation table. WRITE=1 saves docs/evidence/triage-eval.md
> $(PY) triage/triage.py eval $(if $(WRITE),--write,)

intel-test: sentinel-test triage-test  ## all Stage 6 tests
> $(PY) -m pytest response/tests/test_advisor_hook.py -q
