# source this file:  source scripts/env.sh
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566   # AWS CLI v2 honours this for every service
export LOCALSTACK_ENDPOINT=http://localhost:4566

# acct <name-or-id> <aws args...>  e.g.  acct workload ec2 describe-vpcs
# Runs the AWS CLI as another account (on LocalStack the access key IS the account ID).
acct() {
  local id
  case "$1" in
    management)  id=111111111111 ;;
    log_archive) id=222222222222 ;;
    security)    id=333333333333 ;;
    workload)    id=444444444444 ;;
    *)           id="$1" ;;
  esac
  shift
  AWS_ACCESS_KEY_ID="$id" aws "$@"
}