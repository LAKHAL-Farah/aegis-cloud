# Stage 4 targets. Included by the main Makefile (same .RECIPEPREFIX).
RESP_DIR := response
RESP_STATE := build/response
ENDPOINT ?= http://localhost:4566
APPROVER ?= file

.PHONY: response-install response-test respond-plan respond-up respond-down respond-log respond-pending \
        respond-approve respond-deny respond-audit respond-rollback stage4-run lambda-package

response-install:  ## install response dependencies into the venv
> .venv/bin/pip install -r $(RESP_DIR)/requirements.txt

response-test:  ## playbook, approval, audit and Lambda tests (moto, no LocalStack needed)
> $(PY) -m pytest $(RESP_DIR)/tests -q

respond-plan:  ## DRY RUN in the foreground: plans and notifies, changes nothing
> $(PY) $(RESP_DIR)/respond.py --endpoint $(ENDPOINT) watch

respond-up:  ## run the responder in the background and ACT after approval (APPROVER=file|telegram)
> mkdir -p $(RESP_STATE)
> nohup $(PY) $(RESP_DIR)/respond.py --endpoint $(ENDPOINT) watch --execute --approver $(APPROVER) > $(RESP_STATE)/responder.log 2>&1 & echo $$! > $(RESP_STATE)/responder.pid
> sleep 2
> if kill -0 "$$(cat $(RESP_STATE)/responder.pid)" 2>/dev/null; then echo "responder running (pid $$(cat $(RESP_STATE)/responder.pid), approver=$(APPROVER))"; else echo "responder failed to start:"; cat $(RESP_STATE)/responder.log; exit 1; fi

respond-down:  ## stop the background responder
> if [ -f $(RESP_STATE)/responder.pid ]; then kill "$$(cat $(RESP_STATE)/responder.pid)" 2>/dev/null || true; rm -f $(RESP_STATE)/responder.pid; echo "responder stopped"; else echo "responder was not running"; fi

respond-log:  ## show the responder log
> tail -n 40 $(RESP_STATE)/responder.log

respond-pending:  ## approvals waiting for a person (file approver)
> $(PY) $(RESP_DIR)/respond.py pending

respond-approve:  ## approve a pending action: make respond-approve ID=<incident id>
> test -n "$(ID)" || { echo "usage: make respond-approve ID=<incident id from make respond-pending>"; exit 1; }
> $(PY) $(RESP_DIR)/respond.py approve $(ID)

respond-deny:  ## deny a pending action: make respond-deny ID=<incident id>
> test -n "$(ID)" || { echo "usage: make respond-deny ID=<incident id>"; exit 1; }
> $(PY) $(RESP_DIR)/respond.py deny $(ID)

respond-audit:  ## print the audit trail and verify its hash chain
> $(PY) $(RESP_DIR)/respond.py audit

respond-rollback:  ## re-activate the keys an incident deactivated: make respond-rollback ID=<incident id>
> test -n "$(ID)" || { echo "usage: make respond-rollback ID=<incident id>"; exit 1; }
> $(PY) $(RESP_DIR)/respond.py --endpoint $(ENDPOINT) rollback $(ID)

stage4-run:  ## the measured run: detector up, attack, respond, verify, scorecard. LABEL=stage4-v1 [APPROVER=auto|telegram]
> test -n "$(LABEL)" || { echo "usage: make stage4-run LABEL=stage4-v1"; exit 1; }
> $(MAKE) --no-print-directory detect-down
> rm -rf build/findings; mkdir -p build/alerts build/findings
> $(MAKE) --no-print-directory detect-up
> $(PY) $(RESP_DIR)/tools/measure.py --label $(LABEL) --approver $(if $(filter file,$(APPROVER)),auto,$(APPROVER)) --endpoint $(ENDPOINT) || { $(MAKE) --no-print-directory detect-down; exit 1; }
> $(MAKE) --no-print-directory detect-down

lambda-package:  ## build build/lambda/aegis-respond.zip and print its sha256
> bash $(RESP_DIR)/package_lambda.sh
