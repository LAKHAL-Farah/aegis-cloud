#!/usr/bin/env bash
# Exit 0: no drift. Exit 2: drift in at least one root. Exit 1: a plan errored.
set -uo pipefail
cd "$(dirname "$0")/.."

roots=(log-archive management security workload)
drift=0
for r in "${roots[@]}"; do
  dir="terraform/live/$r"
  terraform -chdir="$dir" init -input=false -reconfigure >/dev/null 2>&1 || { echo "[$r] init failed"; exit 1; }
  terraform -chdir="$dir" plan -input=false -lock=false -detailed-exitcode -out=drift.tfplan >/dev/null 2>"$dir/drift.err"
  code=$?
  case $code in
    0) echo "[$r] no drift" ;;
    2) echo "[$r] DRIFT detected:"
       terraform -chdir="$dir" show -no-color drift.tfplan | grep -E '^\s+[#~+-]' | head -n 20
       drift=1 ;;
    *) echo "[$r] plan error:"; head -n 10 "$dir/drift.err"; exit 1 ;;
  esac
  rm -f "$dir/drift.tfplan" "$dir/drift.err"
done
[ "$drift" -eq 0 ] && exit 0 || exit 2