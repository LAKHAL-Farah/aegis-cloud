locals {
  archive_bucket_name = "${var.name_prefix}-log-archive-${var.log_archive_account_id}"
  archive_bucket_arn  = "arn:aws:s3:::${local.archive_bucket_name}"
  access_bucket_name  = "${local.archive_bucket_name}-access-logs"
  trail_arn           = "arn:aws:cloudtrail:${var.region}:${var.management_account_id}:trail/${var.trail_name}"
  log_group_name      = "/aegis/cloudtrail/${var.trail_name}"
  cwl_enabled         = var.create_trail && var.create_trail_key && var.enable_cloudwatch_logs
}

# ---------- log_archive account: key + buckets ----------

resource "aws_kms_key" "archive" {
  #checkov:skip=CKV_AWS_109:Key policies must use Resource "*" (it means "this key") and delegate to IAM via the account root
  #checkov:skip=CKV_AWS_111:Same: key-policy statements apply to this key only
  #checkov:skip=CKV_AWS_356:Same: Resource "*" in a key policy is the key itself
  count                   = var.create_log_archive ? 1 : 0
  description             = "AegisCloud log archive encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.log_archive_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailToEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "AllowConfigToEncrypt"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceAccount" = var.source_account_ids } }
      },
    ]
  })
}

resource "aws_kms_alias" "archive" {
  count         = var.create_log_archive ? 1 : 0
  name          = "alias/${var.name_prefix}-log-archive"
  target_key_id = aws_kms_key.archive[0].key_id
}

module "access_logs" {
  count       = var.create_log_archive ? 1 : 0
  source      = "../secure-bucket"
  bucket_name = local.access_bucket_name

  expiration_days = 90

  extra_policy_statements = [{
    Sid       = "AllowS3ServerAccessLogDelivery"
    Effect    = "Allow"
    Principal = { Service = "logging.s3.amazonaws.com" }
    Action    = "s3:PutObject"
    Resource  = "arn:aws:s3:::${local.access_bucket_name}/s3-access/*"
    Condition = { StringEquals = { "aws:SourceAccount" = var.log_archive_account_id } }
  }]
}

module "archive" {
  count       = var.create_log_archive ? 1 : 0
  source      = "../secure-bucket"
  bucket_name = local.archive_bucket_name

  kms_key_arn           = aws_kms_key.archive[0].arn
  logging_target_bucket = local.access_bucket_name
  depends_on            = [module.access_logs]

  extra_policy_statements = [
    {
      Sid       = "AllowCloudTrailAclCheck"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = local.archive_bucket_arn
      Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
    },
    {
      Sid       = "AllowCloudTrailWrite"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${local.archive_bucket_arn}/AWSLogs/*"
      Condition = {
        StringEquals = {
          "s3:x-amz-acl"  = "bucket-owner-full-control"
          "aws:SourceArn" = local.trail_arn
        }
      }
    },
    {
      Sid       = "AllowConfigAclCheck"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
      Resource  = local.archive_bucket_arn
      Condition = { StringEquals = { "aws:SourceAccount" = var.source_account_ids } }
    },
    {
      Sid       = "AllowConfigWrite"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${local.archive_bucket_arn}/config/AWSLogs/*"
      Condition = {
        StringEquals = {
          "s3:x-amz-acl"      = "bucket-owner-full-control"
          "aws:SourceAccount" = var.source_account_ids
        }
      }
    },
  ]
}

# ---------- management account: the trail ----------

resource "aws_kms_key" "trail" {
  #checkov:skip=CKV_AWS_109:Key policies must use Resource "*" (it means "this key") and delegate to IAM via the account root
  #checkov:skip=CKV_AWS_111:Same: key-policy statements apply to this key only
  #checkov:skip=CKV_AWS_356:Same: Resource "*" in a key policy is the key itself
  count                   = var.create_trail_key ? 1 : 0
  description             = "AegisCloud CloudTrail encryption key (management account)"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.management_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailToEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "AllowCloudWatchLogsToUseTheKey"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = { ArnLike = { "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${var.management_account_id}:log-group:${local.log_group_name}" } }
      },
    ]
  })
}

# ---------- CIS 3.4: the trail also writes to CloudWatch Logs, where the CIS section 4 metric filters live ----------

resource "aws_cloudwatch_log_group" "trail" {
  count             = local.cwl_enabled ? 1 : 0
  name              = local.log_group_name
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = aws_kms_key.trail[0].arn
}

resource "aws_iam_role" "trail_to_cwl" {
  count = local.cwl_enabled ? 1 : 0
  name  = "${var.name_prefix}-trail-to-cloudwatch-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
    }]
  })
}

resource "aws_iam_role_policy" "trail_to_cwl" {
  count = local.cwl_enabled ? 1 : 0
  name  = "write-trail-events"
  role  = aws_iam_role.trail_to_cwl[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail[0].arn}:log-stream:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV2_AWS_10:False positive. The attributes below ARE set (CIS 3.4) but Checkov's graph cannot follow the count-guarded reference. Proven instead by logging.tftest.hcl and the live check `trail_cloudwatch_logs` in compliance_score.py
  #checkov:skip=CKV_AWS_252:No SNS topic by design; trail events reach responders through EventBridge to n8n in Stage 4 (ADR-0005)
  count                         = var.create_trail ? 1 : 0
  name                          = var.trail_name
  s3_bucket_name                = var.log_bucket_name
  kms_key_id                    = var.create_trail_key ? aws_kms_key.trail[0].arn : var.kms_key_arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  is_organization_trail         = var.is_organization_trail
  enable_logging                = true

  cloud_watch_logs_group_arn = length(aws_cloudwatch_log_group.trail) == 0 ? null : "${aws_cloudwatch_log_group.trail[0].arn}:*"
  cloud_watch_logs_role_arn  = length(aws_iam_role.trail_to_cwl) == 0 ? null : aws_iam_role.trail_to_cwl[0].arn

  depends_on = [aws_iam_role_policy.trail_to_cwl]
}

