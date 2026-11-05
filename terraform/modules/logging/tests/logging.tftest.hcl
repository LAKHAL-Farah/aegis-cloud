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

run "trail_goes_to_an_encrypted_log_group_when_enabled" {
  command = plan

  variables {
    create_trail           = true
    create_trail_key       = true
    enable_cloudwatch_logs = true
    log_bucket_name        = "aegis-log-archive-222222222222"
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.trail) == 1 && aws_cloudwatch_log_group.trail[0].retention_in_days >= 365
    error_message = "CIS 3.4: the trail needs a log group that keeps events for at least a year."
  }

  assert {
    condition     = aws_cloudtrail.main[0].cloud_watch_logs_group_arn != null
    error_message = "CIS 3.4: the trail must deliver to CloudWatch Logs."
  }

  assert {
    condition     = output.log_group_name == "/aegis/cloudtrail/aegis-org-trail"
    error_message = "The monitoring module and compliance_score.py look the group up by this name."
  }
}

run "no_log_group_unless_asked" {
  command = plan

  variables {
    create_trail     = true
    create_trail_key = true
    log_bucket_name  = "aegis-log-archive-222222222222"
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.trail) == 0 && aws_cloudtrail.main[0].cloud_watch_logs_group_arn == null
    error_message = "enable_cloudwatch_logs defaults to false so the Stage 1 roots keep planning the same."
  }
}
