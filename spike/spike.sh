#!/usr/bin/env bash
# AegisCloud feasibility spike: what does your LocalStack tier really support?
# Usage: LOCALSTACK_AUTH_TOKEN=... make up && make spike
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p logs

export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
EP="${LOCALSTACK_ENDPOINT:-http://localhost:4566}"
REPORT="spike-report.md"
awsl() { aws --endpoint-url "$EP" "$@"; }

NAMES=(); RESULTS=(); NOTES=()
record() {
  NAMES+=("$1"); RESULTS+=("$2"); NOTES+=("${3:-}")
  printf '%-34s %s\n' "$1" "$2"
}

# tf_probe NAME TARGET...   -> terraform apply limited to the targets (and their dependencies)
tf_probe() {
  local name="$1"; shift
  local args=(); for t in "$@"; do args+=("-target=$t"); done
  if terraform apply -auto-approve -input=false "${args[@]}" >"logs/$name.log" 2>&1; then
    record "apply:$name" "PASS"
  else
    record "apply:$name" "FAIL" "$(grep -m1 -i 'error' "logs/$name.log" | cut -c1-110)"
  fi
}

# check NAME REGEX CMD...   -> command must succeed AND output must match REGEX (if non-empty)
check() {
  local name="$1" pattern="$2"; shift 2
  local out
  if out=$("$@" 2>&1); then
    if [[ -z "$pattern" ]] || grep -Eq "$pattern" <<<"$out"; then
      record "$name" "PASS"
    else
      record "$name" "EMPTY" "call worked but output did not match /$pattern/ (stub?)"
    fi
  else
    record "$name" "FAIL" "$(head -c 110 <<<"$out" | tr '\n' ' ')"
  fi
}

curl -sf "$EP/_localstack/health" >/dev/null || { echo "LocalStack not reachable at $EP (run: make up)"; exit 1; }
echo "== LocalStack health =="; curl -s "$EP/_localstack/health" | head -c 400; echo; echo

terraform init -upgrade -input=false >logs/init.log 2>&1 || { echo "terraform init failed, see logs/init.log"; exit 1; }

echo "== 1. Terraform apply probes =="
tf_probe organizations  aws_organizations_policy_attachment.workloads
tf_probe logging        aws_cloudtrail.main
tf_probe config         aws_config_config_rule.s3_public_read
tf_probe guardduty      aws_guardduty_detector.main
tf_probe securityhub    aws_securityhub_standards_subscription.cis
tf_probe eventing       aws_sqs_queue_policy.allow_events aws_cloudwatch_event_target.to_sqs
echo

echo "== 2. Behaviour probes (does it DO something, not just exist?) =="
# Multi-account trick: a 12-digit access key becomes the account ID
check "api:multi-account-sts" "111111111111" \
  env AWS_ACCESS_KEY_ID=111111111111 aws --endpoint-url "$EP" sts get-caller-identity

check "api:org-describe"  "Organization"  awsl organizations describe-organization
check "api:scp-listed"    "aegis-protect" awsl organizations list-policies --filter SERVICE_CONTROL_POLICY

check "api:trail-status"  "IsLogging.*true" awsl cloudtrail get-trail-status --name aegis-spike-trail
awsl s3api create-bucket --bucket aegis-spike-activity >/dev/null 2>&1
sleep 3
check "api:trail-lookup-events" "CreateBucket" awsl cloudtrail lookup-events --max-results 20 --query 'Events[].EventName'
check "api:trail-delivers-to-s3" "CloudTrail|AWSLogs" awsl s3 ls "s3://aegis-spike-trail-logs" --recursive

check "api:config-recording"  "recording.*true"       awsl configservice describe-configuration-recorder-status
check "api:config-rule"       "S3_BUCKET_PUBLIC_READ" awsl configservice describe-config-rules
check "api:config-compliance" "ComplianceSummary"     awsl configservice get-compliance-summary-by-config-rule

DID=$(awsl guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null)
check "api:guardduty-detector" "^[a-z0-9]{10,}" echo "${DID:-none}"
if [[ -n "${DID:-}" && "$DID" != "None" ]]; then
  awsl guardduty create-sample-findings --detector-id "$DID" >/dev/null 2>&1
  check "api:guardduty-findings" "[a-z0-9]{10,}" awsl guardduty list-findings --detector-id "$DID" --query 'FindingIds[0]' --output text
fi

check "api:securityhub-hub"       "HubArn" awsl securityhub describe-hub
check "api:securityhub-standards" "cis"    awsl securityhub get-enabled-standards
check "api:securityhub-findings"  ""       awsl securityhub get-findings --max-items 1

awsl events put-events --entries '[{"Source":"aegis.spike","DetailType":"spike","Detail":"{\"hello\":\"world\"}"}]' >/dev/null 2>&1
QURL=$(awsl sqs get-queue-url --queue-name aegis-spike-findings --query QueueUrl --output text 2>/dev/null)
check "api:eventbridge-to-sqs" "aegis.spike" awsl sqs receive-message --queue-url "${QURL:-x}" --wait-time-seconds 3
echo

{
  echo "# AegisCloud spike report"
  echo
  echo "Generated: $(date -u +%FT%TZ)  |  Endpoint: $EP"
  echo
  echo "| Probe | Result | Notes |"
  echo "|---|---|---|"
  for i in "${!NAMES[@]}"; do
    echo "| ${NAMES[$i]} | ${RESULTS[$i]} | ${NOTES[$i]} |"
  done
  echo
  echo "## How to read this"
  echo "- **PASS** on apply AND behaviour: rely on LocalStack for this service."
  echo "- **PASS** on apply but **EMPTY/FAIL** on behaviour: the resource is a stub. Build your own logic (Wazuh rules, Lambda checks) and document it as a LocalStack limitation."
  echo "- **FAIL** on apply: check spike/logs/<name>.log. Often a provider argument issue, not a missing service."
  echo "- SCP enforcement is NOT tested here: the management account is exempt in real AWS. Stage 1 tests it with a member account."
} > "$REPORT"

echo "Report written to spike/$REPORT"
pass=$(printf '%s\n' "${RESULTS[@]}" | grep -c PASS || true)
echo "PASS: $pass / ${#RESULTS[@]}"
