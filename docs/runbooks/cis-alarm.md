# A CIS section 4 alarm fired

## Symptom
An alarm named `aegis-cis-4_<nn>_<what>` is in ALARM, or its SNS notification arrived. It means CloudTrail recorded one
of the 15 event families CIS wants watched (unauthorized calls, root use, IAM / SG / NACL / route / VPC / S3 policy
changes, CMK deletion, console failures, Config or Organizations changes).

## Check
1. Which control? The alarm name carries it (`4_10_security_group_changes` = CIS 4.10).
2. Who and what exactly: look the event up. On real AWS: CloudWatch Logs Insights on `/aegis/cloudtrail/aegis-org-trail`,
   `filter eventName = "AuthorizeSecurityGroupIngress"`. On LocalStack these alarms cannot fire (see
   `docs/evidence/ops-probe.md`; LocalStack also fails to match the compound CIS patterns, `docs/evidence/filter-probe.md`); use the detector instead: `ls build/findings`, or the Kibana attack timeline.
3. Was it us? Compare with the last `terraform apply` and `docs/evidence/scorecards/`: our own attack runs trigger several of these on purpose.

## Fix
* Expected change (a planned apply, an attack run): note it, set the alarm back with `aws cloudwatch set-alarm-state`, done.
* Unexpected change: treat it as an incident. Run the matching playbook (`response/` handles leaked keys and public
  buckets) or revert the change through Terraform, never by hand. Keep the CloudTrail event as evidence.

## Verify
`make score` shows control 4.x passing, and the alarm returns to OK on its own after the next quiet period (5 minutes).
