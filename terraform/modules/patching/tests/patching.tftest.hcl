mock_provider "aws" {}

run "baseline_approves_only_security_and_bugfix" {
  command = plan

  assert {
    condition = anytrue([
      for f in one(aws_ssm_patch_baseline.this.approval_rule).patch_filter :
      f.key == "CLASSIFICATION" && toset(f.values) == toset(["Security", "Bugfix"])
    ])
    error_message = "Feature updates must not be installed unattended."
  }
}

run "window_targets_the_patch_group_tag_the_compute_module_sets" {
  command = plan

  assert {
    condition     = one(aws_ssm_maintenance_window_target.this.targets).key == "tag:Patch Group" && one(aws_ssm_maintenance_window_target.this.targets).values == tolist(["aegis-workload"])
    error_message = "The compute module tags instances `Patch Group` = aegis-workload; the window must match, or nothing is patched."
  }
}

run "unassociated_targets_are_not_allowed" {
  command = plan

  assert {
    condition     = aws_ssm_maintenance_window.this.allow_unassociated_targets == false
    error_message = "A window may only touch registered targets."
  }
}
