#!/usr/bin/env bash
# Feed each sample line to wazuh-logtest inside the container and compare the rule that would raise an alert.
# Line N of samples.jsonl must match line N of expected.txt (NONE = no alert would be generated).
# Do NOT add -q: in quiet mode wazuh-logtest prints nothing. Level-0 parent rules never alert, so they count as NONE.
set -uo pipefail
cd "$(dirname "$0")"
docker ps --format '{{.Names}}' | grep -q '^aegis-wazuh$' || { echo "start it first: make siem-up PROFILE=wazuh" >&2; exit 1; }
mapfile -t samples < <(tr -d '\r' < tests/samples.jsonl | sed '/^$/d')
mapfile -t wants   < <(tr -d '\r' < tests/expected.txt  | sed '/^$/d')
[ "${#samples[@]}" -eq "${#wants[@]}" ] || { echo "samples (${#samples[@]}) and expected (${#wants[@]}) differ in length" >&2; exit 1; }

rule_that_alerts() {   # stdin: wazuh-logtest output -> rule id, or NONE
  local out; out=$(cat)
  if grep -q 'Alert to be generated' <<<"$out"; then
    grep -oE "id: '[0-9]+'" <<<"$out" | tail -1 | grep -oE '[0-9]+'
  else
    echo NONE
  fi
}

fail=0
for i in "${!samples[@]}"; do
  n=$((i+1)); want="${wants[$i]}"
  out=$(printf '%s\n' "${samples[$i]}" | docker exec -i aegis-wazuh /var/ossec/bin/wazuh-logtest 2>&1)
  got=$(rule_that_alerts <<<"$out")
  if [ "$got" = "$want" ]; then echo "ok   sample $n -> $got"
  else echo "FAIL sample $n: wanted $want, got $got"; [ -n "${VERBOSE:-}" ] && printf '%s\n' "$out" | sed 's/^/     | /'; fail=1; fi
done
exit $fail
