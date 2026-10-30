locals {
  data_bucket = "${var.name_prefix}-data-${var.account_id}"
  logs_bucket = "${var.name_prefix}-data-logs-${var.account_id}"
}

resource "aws_kms_key" "data" {
  #checkov:skip=CKV_AWS_109:Key policies must use Resource "*" (it means "this key")
  #checkov:skip=CKV_AWS_111:Same: key-policy statements apply to this key only
  #checkov:skip=CKV_AWS_356:Same: Resource "*" in a key policy is the key itself
  description             = "AegisCloud workload data key"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = { ArnLike = { "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${var.account_id}:*" } }
      },
    ]
  })
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name_prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}

module "logs" {
  source          = "../secure-bucket"
  bucket_name     = local.logs_bucket
  expiration_days = 90

  extra_policy_statements = [{
    Sid       = "AllowS3ServerAccessLogDelivery"
    Effect    = "Allow"
    Principal = { Service = "logging.s3.amazonaws.com" }
    Action    = "s3:PutObject"
    Resource  = "arn:aws:s3:::${local.logs_bucket}/s3-access/*"
    Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
  }]
}

module "bucket" {
  source                = "../secure-bucket"
  bucket_name           = local.data_bucket
  kms_key_arn           = aws_kms_key.data.arn
  logging_target_bucket = local.logs_bucket
  depends_on            = [module.logs]
}