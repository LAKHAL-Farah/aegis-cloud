# ADR-0001: Multi-account through 12-digit access keys

* Status: accepted
* Date: 2026-10-28

## Context
The target design is a four-account landing zone (management, log-archive, security, workload). LocalStack identifies the account by the access key when it is a 12-digit number. The spike confirmed `sts get-caller-identity` returns the chosen account ID.

## Decision
Each account has its own Terraform root (`terraform/live/<account>`), all using the identical provider block from `_shared/common.tf`. The access key is `accounts[account_name]`. State is isolated per root.

## Consequences
* (+) Real isolation of state and blast radius; cross-account reads go through remote state or explicit variables, as in real AWS.
* (+) On real AWS only the `provider` block changes (assume-role instead of access key).
* (-) Account creation through Organizations may yield IDs that differ from the keys; member accounts are therefore opt-in (`create_member_accounts`).