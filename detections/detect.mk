# Stage 3 targets. Included by the main Makefile (same .RECIPEPREFIX).
DETECT_DIR := detections
DETECT_OPTS ?=

.PHONY: detect-install detect-test detect-rules detect-probe detect-watch detect-up detect-down detect-log \
        stage3-run stage3-rescore detect-report siem-up siem-down siem-setup wazuh-prepare wazuh-test wazuh-bridge

detect-install:  ## install detection dependencies into the venv
> .venv/bin/pip install -r $(DETECT_DIR)/requirements.txt

detect-test:  ## unit tests of the engine, rules, ASFF and replay (no LocalStack needed)
> $(PY) -m pytest $(DETECT_DIR)/tests siem/tests report/tests -q

detect-rules:  ## list the rules as a markdown table
> $(PY) $(DETECT_DIR)/detect.py rules

detect-probe:  ## answer the telemetry questions on the purple twin, writes build/logsource.json
> $(PY) $(DETECT_DIR)/tools/probe_telemetry.py

detect-watch:  ## run the detector in the foreground (Ctrl-C to stop)
> $(PY) $(DETECT_DIR)/detect.py watch $(DETECT_OPTS)

detect-up:  ## run the detector in the background (pid in build/detector.pid, log in build/detector.log)
> mkdir -p build build/alerts build/findings
> nohup $(PY) $(DETECT_DIR)/detect.py watch $(DETECT_OPTS) > build/detector.log 2>&1 & echo $$! > build/detector.pid
> sleep 3
> if kill -0 "$$(cat build/detector.pid)" 2>/dev/null; then echo "detector running (pid $$(cat build/detector.pid))"; else echo "detector failed to start:"; cat build/detector.log; exit 1; fi

detect-down:  ## stop the background detector
> if [ -f build/detector.pid ]; then kill "$$(cat build/detector.pid)" 2>/dev/null || true; rm -f build/detector.pid; echo "detector stopped"; else echo "detector was not running"; fi

detect-log:  ## show the detector log
> tail -n 40 build/detector.log

stage3-run:  ## the scored run: fresh alert folder, detector up, 12 attacks, settle, scorecard. LABEL=stage3-v1
> test -n "$(LABEL)" || { echo "usage: make stage3-run LABEL=stage3-v1"; exit 1; }
> $(MAKE) --no-print-directory detect-down
> if [ -d build/alerts ] && [ -n "$$(ls -A build/alerts 2>/dev/null)" ]; then mkdir -p build/alerts-archive && mv build/alerts build/alerts-archive/$$(date +%Y%m%dT%H%M%S); fi
> rm -rf build/findings; mkdir -p build/alerts build/findings
> $(MAKE) --no-print-directory detect-up
> $(PY) cloudpurple/run_attacks.py --label $(LABEL) --settle $(or $(SETTLE),25) $(ARGS) || { $(MAKE) --no-print-directory detect-down; exit 1; }
> $(MAKE) --no-print-directory detect-down

stage3-rescore:  ## re-score a saved run against the alerts on disk: make stage3-rescore FROM=stage3-v1 LABEL=stage3-v1-b
> $(PY) cloudpurple/run_attacks.py --rescore $(FROM) --label $(LABEL) $(ARGS)

detect-report:  ## before/after table + ATT&CK matrix: make detect-report BEFORE=baseline AFTER=stage3-v1
> $(PY) report/attack_matrix.py --before $(or $(BEFORE),baseline) --after $(or $(AFTER),stage3-v1)

# ---------- SIEM (OpenSearch + Dashboards, optional Wazuh) ----------
siem-up:  ## start OpenSearch + Dashboards (add PROFILE=wazuh for the Wazuh manager too)
> docker compose -f docker-compose.siem.yml $(if $(PROFILE),--profile $(PROFILE)) up -d
> @echo "OpenSearch http://localhost:9200   Dashboards http://localhost:5601"

siem-down:  ## stop the SIEM stack
> docker compose -f docker-compose.siem.yml --profile wazuh down

siem-setup:  ## create index templates and data views
> $(PY) siem/opensearch_setup.py

wazuh-prepare:  ## build siem/wazuh/ossec.conf from the image's default config
> bash siem/wazuh/prepare.sh

wazuh-test:  ## test the Wazuh rules with wazuh-logtest (needs `make siem-up PROFILE=wazuh`)
> bash siem/wazuh/test_rules.sh

wazuh-bridge:  ## turn Wazuh alerts into contract alerts (foreground)
> $(PY) siem/wazuh_bridge.py