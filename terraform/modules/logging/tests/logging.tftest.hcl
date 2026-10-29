mock_provider "aws" {}

variables {
  log_archive_account_id = "222222222222"
  management_account_id  = "111111111111"
  source_account_ids     = ["111111111111", "444444444444"]
}

run "archive_key_is_rotated" {
  command = plan

  variables {
    create_log_archive = true
  }

  assert {
    condition     = aws_kms_key.archive[0].enable_key_rotation == true
    error_message = "Customer-managed keys must have rotation enabled (CIS 3.8)."
  }
}

run "trail_is_multi_region_validated_and_encrypted" {
  command = plan

  variables {
    create_trail    = true
    log_bucket_name = "aegis-log-archive-222222222222"
    kms_key_arn     = "arn:aws:kms:us-east-1:222222222222:key/00000000-0000-0000-0000-000000000000"
  }

  assert {
    condition     = aws_cloudtrail.main[0].is_multi_region_trail == true
    error_message = "Trail must be multi-region (CIS 3.1)."
  }

  assert {
    condition     = aws_cloudtrail.main[0].enable_log_file_validation == true
    error_message = "Log file validation must be on (CIS 3.2)."
  }

  assert {
    condition     = aws_cloudtrail.main[0].kms_key_id != null
    error_message = "Trail must be encrypted with KMS (CIS 3.7)."
  }
}

run "nothing_is_created_by_default" {
  command = plan

  assert {
    condition     = length(aws_kms_key.archive) == 0 && length(aws_cloudtrail.main) == 0
    error_message = "Both toggles default to false."
  }
}