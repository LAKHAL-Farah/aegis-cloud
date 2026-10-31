# The twin must actually be vulnerable, and the hardened twin must actually be hardened.
# If someone "fixes" the vulnerable twin, these tests fail: the range stays honest.
mock_provider "aws" {}

variables {
  name       = "t"
  account_id = "555555555555"
  ami_id     = "ami-00000000"
}

run "vulnerable_twin_is_vulnerable" {
  command = plan

  variables {
    hardened = false
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.data.block_public_acls == false && aws_s3_bucket_public_access_block.data.restrict_public_buckets == false
    error_message = "The vulnerable twin must have Block Public Access off."
  }

  assert {
    condition     = aws_kms_key.data.enable_key_rotation == false
    error_message = "The vulnerable twin must not rotate its key."
  }

  assert {
    condition     = length(aws_security_group.legacy_open) == 1
    error_message = "The vulnerable twin must contain the world-open SSH group."
  }

  assert {
    condition     = aws_iam_user.dev_svc.permissions_boundary == null
    error_message = "The vulnerable twin's stolen user must have no boundary."
  }

  assert {
    condition     = one(aws_instance.app[0].metadata_options).http_tokens == "optional"
    error_message = "The vulnerable twin must allow IMDSv1."
  }
}

run "hardened_twin_is_hardened" {
  command = plan

  variables {
    hardened                 = true
    permissions_boundary_arn = "arn:aws:iam::444444444444:policy/aegis-permission-boundary"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.data.block_public_acls == true && aws_s3_bucket_public_access_block.data.restrict_public_buckets == true
    error_message = "The hardened twin must block public access."
  }

  assert {
    condition     = aws_kms_key.data.enable_key_rotation == true
    error_message = "The hardened twin must rotate its key."
  }

  assert {
    condition     = length(aws_security_group.legacy_open) == 0
    error_message = "No world-open group in the hardened twin."
  }

  assert {
    condition     = aws_iam_user.dev_svc.permissions_boundary != null && aws_iam_user.intern.permissions_boundary != null
    error_message = "Both attacker-reachable users must carry the boundary."
  }

  assert {
    condition     = one(aws_instance.app[0].metadata_options).http_tokens == "required"
    error_message = "IMDSv2 required in the hardened twin."
  }

  assert {
    condition     = length(aws_cloudtrail.this.event_selector) == 0
    error_message = "No event selectors in the hardened twin (the SCP denies PutEventSelectors)."
  }
}

run "both_twins_hold_the_same_victim_assets" {
  command = plan

  variables {
    hardened = false
  }

  assert {
    condition     = length(aws_s3_object.seed) == 12
    error_message = "Twelve synthetic objects: the attack scripts rely on the naming."
  }
}