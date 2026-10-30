mock_provider "aws" {}

variables {
  delivery_bucket_name = "aegis-log-archive-222222222222"
}

run "rule_set_matches_cis_mapping" {
  command = plan

  assert {
    condition     = length(output.rule_names) == 15
    error_message = "docs/cis-mapping.md lists 15 Config rules; update both together."
  }

  assert {
    condition     = contains(output.rule_names, "root-account-mfa-enabled") && contains(output.rule_names, "restricted-ssh")
    error_message = "Core CIS rules are missing."
  }
}

run "recorder_records_global_resources" {
  command = plan

  assert {
    condition     = one(aws_config_configuration_recorder.this.recording_group).include_global_resource_types == true
    error_message = "At least one region must record global resources (CIS 3.5)."
  }
}