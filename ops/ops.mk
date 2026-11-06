# Stage 5 targets. Included by the main Makefile (same .RECIPEPREFIX).
OPS_DIR := ops

.PHONY: ops-probe-filters ops-slo-reset ops-install ops-test ops-probe ops-up ops-down ops-status ops-watchdog ops-slo ops-drill chaos-list chaos stage5-run

ops-install:  ## install ops dependencies into the venv
> .venv/bin/pip install -r $(OPS_DIR)/requirements.txt -r detections/requirements.txt -r response/requirements.txt

ops-test:  ## unit tests: watchdog, SLOs, restore drill, chaos logic, probe (no LocalStack needed)
> $(PY) -m pytest $(OPS_DIR)/tests -q

ops-probe:  ## which Stage 5 features does this LocalStack implement? writes docs/evidence/ops-probe.md. WAIT=150 tests alarm evaluation
> $(PY) $(OPS_DIR)/tools/probe_ops.py $(if $(WAIT),--wait $(WAIT),)

ops-probe-filters:  ## which log filter patterns does LocalStack match? (simple ... the real CIS ones)
> $(PY) $(OPS_DIR)/tools/probe_filters.py

ops-up:  ## start the supervised detector + responder (checkpoint, resume, heartbeats). Stop other detectors first (make detect-down)
> $(PY) $(OPS_DIR)/ops.py up

ops-down:  ## stop them
> $(PY) $(OPS_DIR)/ops.py down

ops-status:  ## one health check
> $(PY) $(OPS_DIR)/ops.py status

ops-watchdog:  ## watch and heal in the foreground (Ctrl-C to stop). PUBLISH=1 sends ComponentUp to CloudWatch
> $(PY) $(OPS_DIR)/ops.py watchdog --heal $(if $(PUBLISH),--publish,)

ops-slo-reset:  ## start the SLO measurement from now: older history is ignored, not deleted
> $(PY) $(OPS_DIR)/ops.py slo --reset

ops-slo:  ## SLO report for the last 24 h from the watchdog log, the audit trail and the findings. WRITE=1 saves it as evidence
> $(PY) $(OPS_DIR)/ops.py slo $(if $(WRITE),--write,)

ops-drill:  ## backup and restore drill on the workload data bucket (S3 versioning), prints the RTO
> $(PY) $(OPS_DIR)/ops.py drill

chaos-list:  ## the chaos experiments and their hypotheses
> $(PY) $(OPS_DIR)/ops.py chaos list

chaos:  ## one experiment against the live range: make chaos EXP=detector-kill LABEL=stage5-v1 [NORESUME=1]
> test -n "$(EXP)" -a -n "$(LABEL)" || { echo "usage: make chaos EXP=detector-kill LABEL=stage5-v1 [NORESUME=1]"; exit 1; }
> $(PY) $(OPS_DIR)/ops.py chaos run $(EXP) --label $(LABEL) $(if $(NORESUME),--no-resume,)

stage5-run:  ## the scored chaos run, all experiments. LABEL=stage5-v1 (baseline: NORESUME=1 LABEL=stage5-v1-baseline)
> test -n "$(LABEL)" || { echo "usage: make stage5-run LABEL=stage5-v1 [NORESUME=1]"; exit 1; }
> $(MAKE) --no-print-directory detect-down
> $(PY) $(OPS_DIR)/ops.py chaos run all --label $(LABEL) $(if $(NORESUME),--no-resume,)
