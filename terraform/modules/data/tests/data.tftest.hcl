mock_provider "aws" {}

variables {
  account_id = "444444444444"
}

run "data_key_rotates" {
  command = plan

  assert {
    condition     = aws_kms_key.data.enable_key_rotation == true
    error_message = "CMK rotation must be enabled (CIS 3.8)."
  }
}

run "bucket_name_includes_account" {
  command = plan

  assert {
    condition     = output.data_bucket_name == "aegis-data-444444444444"
    error_message = "Bucket naming convention changed; Stage 2 attack scripts depend on it."
  }
}