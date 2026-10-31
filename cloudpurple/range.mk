# CloudPurple (Stage 2) targets. Included by the main Makefile (same .RECIPEPREFIX).
RANGE_TF    := cloudpurple/terraform
RANGE_ROOTS := purple hardened

.PHONY: range-ids range-init range-up range-down range-posture range-gate attack attack-list

range-ids:  ## write the generated hardened account id into the hardened root
> bash cloudpurple/scripts/hardened_ids.sh

range-init: range-ids  ## terraform init both range roots
> for r in $(RANGE_ROOTS); do terraform -chdir=$(RANGE_TF)/$$r init -input=false -reconfigure; done

range-up: range-init  ## build both twins, export attacker credentials
> for r in $(RANGE_ROOTS); do terraform -chdir=$(RANGE_TF)/$$r apply -input=false -auto-approve; done
> $(PY) cloudpurple/export_targets.py

range-down:  ## destroy the purple twin (hardened cannot be fully destroyed by design: use `make reset`)
> terraform -chdir=$(RANGE_TF)/purple destroy -input=false -auto-approve

range-posture:  ## static misconfiguration check of both twins
> $(PY) cloudpurple/posture.py

attack-list:  ## list the 12 scenarios
> $(PY) cloudpurple/run_attacks.py --list

attack:  ## run every attack on both twins, print the scorecard (LABEL=baseline ARGS="--only S04")
> $(PY) cloudpurple/run_attacks.py --label $(or $(LABEL),run) $(ARGS)

range-gate:  ## the range's own CI checks, locally
> terraform fmt -check -recursive $(RANGE_TF)
> for r in $(RANGE_ROOTS); do \
>   TF_DATA_DIR=$(CURDIR)/build/tfdata/range-$$r terraform -chdir=$(RANGE_TF)/$$r init -backend=false -input=false >/dev/null && \
>   TF_DATA_DIR=$(CURDIR)/build/tfdata/range-$$r terraform -chdir=$(RANGE_TF)/$$r validate; done
> terraform -chdir=$(RANGE_TF)/modules/range-target init -backend=false -input=false >/dev/null
> terraform -chdir=$(RANGE_TF)/modules/range-target test
> $(PY) -m pytest cloudpurple/tests -q