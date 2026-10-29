# `roots` is a computed attribute the mock cannot invent as a list, so we hand it one.
mock_provider "aws" {}

override_resource {
  target = aws_organizations_organization.this
  values = {
    roots = [{
      id           = "r-test"
      arn          = "arn:aws:organizations::111111111111:root/o-test/r-test"
      name         = "Root"
      policy_types = []
    }]
  }
}

run "all_four_scps_are_loaded" {
  command = plan

  assert {
    condition     = length(output.scp_names) == 4
    error_message = "Expected 4 SCP files in policies/scp."
  }
}

run "protect_logging_blocks_stop_logging" {
  command = plan

  assert {
    condition     = strcontains(aws_organizations_policy.scp["protect-logging"].content, "cloudtrail:StopLogging")
    error_message = "protect-logging SCP must deny cloudtrail:StopLogging."
  }
}

run "region_lock_lists_allowed_regions" {
  command = plan

  assert {
    condition     = strcontains(aws_organizations_policy.scp["region-lock"].content, "us-east-1")
    error_message = "region-lock SCP must name the allowed regions."
  }
}

run "workloads_ou_gets_every_scp" {
  command = plan

  assert {
    condition     = length([for k, v in aws_organizations_policy_attachment.this : k if startswith(k, "workloads-")]) == 4
    error_message = "The workloads OU must have all four SCPs attached."
  }
}

run "no_member_accounts_by_default" {
  command = plan

  assert {
    condition     = length(aws_organizations_account.member) == 0
    error_message = "Member accounts must be opt-in."
  }
}