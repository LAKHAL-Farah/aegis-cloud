# AegisCloud: one entry point for everything.   `make help` lists targets.
.RECIPEPREFIX := >
SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

ROOTS      := log-archive management security workload
TF_DIR     := terraform/live
MODULES    := $(patsubst terraform/modules/%/,%,$(wildcard terraform/modules/*/))
PY         := .venv/bin/python
AWS_LOCAL  := AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566

.PHONY: help up down reset spike bootstrap init-all apply-all destroy-all \
        fmt fmt-check validate lint test security plan-json gate score drift

help:  ## show targets
> @grep -E '^[a-zA-Z_%-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

# ---------- LocalStack ----------
up:  ## start LocalStack (needs LOCALSTACK_AUTH_TOKEN)
> docker compose up -d
> @echo "waiting for LocalStack..."; \
>  for i in $$(seq 1 60); do curl -sf http://localhost:4566/_localstack/health >/dev/null && break || sleep 2; done
> @curl -s http://localhost:4566/_localstack/health | jq -r '.version // "up"'

down:  ## stop LocalStack
> docker compose down

spike:  ## run the feasibility spike (from the kit)
> bash spike/spike.sh

bootstrap:  ## create the Terraform state bucket (account 000000000000)
> $(AWS_LOCAL) s3api head-bucket --bucket aegis-tfstate 2>/dev/null || $(AWS_LOCAL) s3api create-bucket --bucket aegis-tfstate
> $(AWS_LOCAL) s3api put-bucket-versioning --bucket aegis-tfstate --versioning-configuration Status=Enabled
> @echo "state bucket ready"

# ---------- Terraform lifecycle ----------
init-%:  ## init one root, e.g. make init-workload
> terraform -chdir=$(TF_DIR)/$* init -input=false -reconfigure

plan-%:  ## plan one root
> terraform -chdir=$(TF_DIR)/$* plan -input=false

apply-%:  ## apply one root
> terraform -chdir=$(TF_DIR)/$* apply -input=false -auto-approve

init-all:  ## init all roots
> for r in $(ROOTS); do $(MAKE) --no-print-directory init-$$r; done

apply-all: bootstrap init-all  ## apply all roots in dependency order
> for r in $(ROOTS); do $(MAKE) --no-print-directory apply-$$r; done

destroy-all:  ## destroy all roots in reverse order
> for r in $$(echo $(ROOTS) | tr ' ' '\n' | tac); do \
>   terraform -chdir=$(TF_DIR)/$$r destroy -input=false -auto-approve; done

reset: down up apply-all  ## clean slate: restart LocalStack and rebuild everything

# ---------- Quality gates (same checks CI runs) ----------
fmt:  ## format all Terraform
> terraform fmt -recursive terraform

fmt-check:
> terraform fmt -check -recursive terraform

validate:  ## terraform validate every root (no backend, no LocalStack needed)
> for r in $(ROOTS); do \
>   TF_DATA_DIR=$(CURDIR)/build/tfdata/$$r terraform -chdir=$(TF_DIR)/$$r init -backend=false -input=false >/dev/null && \
>   TF_DATA_DIR=$(CURDIR)/build/tfdata/$$r terraform -chdir=$(TF_DIR)/$$r validate; done

lint:  ## tflint
> tflint --init --config $(CURDIR)/.tflint.hcl
> tflint --recursive --config $(CURDIR)/.tflint.hcl

test:  ## terraform test for every module that has tests
> for m in $(MODULES); do \
>   if [ -d terraform/modules/$$m/tests ]; then \
>     echo "== $$m"; \
>     terraform -chdir=terraform/modules/$$m init -backend=false -input=false >/dev/null && \
>     terraform -chdir=terraform/modules/$$m test; \
>   fi; done

plan-json:  ## offline plans -> build/plans/<root>.json (input for Conftest and the score script)
> mkdir -p build/plans build/tfstate
> trap 'rm -f $(TF_DIR)/*/zz_offline_override.tf' EXIT; \
>  for r in $(ROOTS); do \
>   d=$(TF_DIR)/$$r; \
>   printf 'terraform {\n  backend "local" {\n    path = "%s"\n  }\n}\n' "$(CURDIR)/build/tfstate/$$r.tfstate" > $$d/zz_offline_override.tf; \
>   export TF_DATA_DIR=$(CURDIR)/build/tfdata/$$r; \
>   terraform -chdir=$$d init -input=false -reconfigure >/dev/null; \
>   terraform -chdir=$$d plan -input=false -var offline=true -out=$(CURDIR)/build/plans/$$r.tfplan >/dev/null; \
>   terraform -chdir=$$d show -json $(CURDIR)/build/plans/$$r.tfplan > build/plans/$$r.json; \
>   rm -f $$d/zz_offline_override.tf; \
>   echo "plan json: build/plans/$$r.json"; \
>  done

security: plan-json  ## Checkov + Conftest
> $(PY) -m checkov.main -d $(TF_DIR) --config-file policies/checkov/.checkov.yaml
> conftest test --policy policies/opa build/plans/*.json

gate: fmt-check validate lint test security  ## everything CI runs, locally

score: plan-json  ## compliance score (needs LocalStack running + applied)
> $(PY) scripts/compliance_score.py

drift:  ## nightly-style drift check on all roots
> bash scripts/drift_check.sh