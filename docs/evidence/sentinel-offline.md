# Stage 6 offline evidence: IAM Sentinel on both twins (moto, not LocalStack)

Built through real boto3 calls from the same policy documents as `cloudpurple/terraform/modules/range-target` and
`terraform/modules/iam-baseline`, then read back with the real collector. The live run is `make sentinel-scan`.

## purple twin (no boundary)

1 escalate, 1 standing admin, 0 expected admin, 0 capped, 0 ordinary; 0 unresolved policies.

* `dev-svc` (user): **admin**
* `intern` (user): **escalates**, intern -> ADMIN, via ESC-01

## hardened twin (permission boundary)

0 escalate, 0 standing admin, 1 expected admin, 0 capped, 3 ordinary; 0 unresolved policies.

* `aegis-break-glass-admin` (role): **expected_admin**
* `aegis-deployer` (role): **ordinary**
* `dev-svc` (user): **ordinary**
* `intern` (user): **ordinary**

## Least privilege from the purple twin's observed calls

Action universe: 19521 actions from botocore operation names (436 services, loaded in 6.1 s). An approximation of the IAM action list: it sizes a wildcard, it does not authorise anything.

| Principal | Granted before | Allowed after | Fewer | Coverage of observed calls | Escalation before -> after |
| --- | --- | --- | --- | --- | --- |
| dev-svc | 19521 | 3 | 99.98% | complete (3 checked) | admin -> ordinary |
| intern | 4 | 1 | 75.0% | complete (1 checked) | escalates -> ordinary |

`dev-svc` left out as sensitive: cloudtrail:StopLogging, iam:CreateAccessKey; needs no permission: sts:GetCallerIdentity.

The reduction for a wildcard is dominated by `*` expanding to the whole universe: it says the wildcard was the problem,
not that the generator is clever. The `intern` figure (4 granted, 1 needed) is the honest one.
