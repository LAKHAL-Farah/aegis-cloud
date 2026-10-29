# Unit test: no AWS, no LocalStack. mock_provider fakes the provider so `plan` runs offline.
mock_provider "aws" {}

variables {
  bucket_name = "unit-test-bucket"
}

run "public_access_fully_blocked" {
  command = plan

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.this.block_public_acls,
      aws_s3_bucket_public_access_block.this.block_public_policy,
      aws_s3_bucket_public_access_block.this.ignore_public_acls,
      aws_s3_bucket_public_access_block.this.restrict_public_buckets,
    ])
    error_message = "Block Public Access must be fully enabled (CIS 2.1.5)."
  }
}

run "https_only_policy_present" {
  command = plan

  assert {
    condition     = strcontains(aws_s3_bucket_policy.this.policy, "aws:SecureTransport")
    error_message = "Bucket policy must deny non-TLS requests (CIS 2.1.2)."
  }
}

run "versioning_enabled_by_default" {
  command = plan

  assert {
    condition     = one(aws_s3_bucket_versioning.this.versioning_configuration).status == "Enabled"
    error_message = "Versioning must be enabled by default."
  }
}

run "kms_used_when_key_given" {
  command = plan

  variables {
    kms_key_arn = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"
  }

  assert {
    condition = contains(
      [for r in aws_s3_bucket_server_side_encryption_configuration.this.rule :
      one(r.apply_server_side_encryption_by_default).sse_algorithm],
      "aws:kms"
    )
    error_message = "SSE-KMS expected when a key is supplied (CIS 2.1.1)."
  }
}