locals {
  # rule name -> AWS managed rule identifier + the CIS v1.4 control it supports
  rules = {
    "root-account-mfa-enabled"                 = { source = "ROOT_ACCOUNT_MFA_ENABLED", cis = "1.5" }
    "iam-password-policy"                      = { source = "IAM_PASSWORD_POLICY", cis = "1.8" }
    "iam-user-unused-credentials-check"        = { source = "IAM_USER_UNUSED_CREDENTIALS_CHECK", cis = "1.12" }
    "access-keys-rotated"                      = { source = "ACCESS_KEYS_ROTATED", cis = "1.14" }
    "iam-no-admin-policies"                    = { source = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS", cis = "1.16" }
    "s3-bucket-ssl-requests-only"              = { source = "S3_BUCKET_SSL_REQUESTS_ONLY", cis = "2.1.2" }
    "s3-bucket-level-public-access-prohibited" = { source = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED", cis = "2.1.5" }
    "cloudtrail-enabled"                       = { source = "CLOUD_TRAIL_ENABLED", cis = "3.1" }
    "cloud-trail-log-file-validation-enabled"  = { source = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED", cis = "3.2" }
    "s3-bucket-logging-enabled"                = { source = "S3_BUCKET_LOGGING_ENABLED", cis = "3.6" }
    "cloud-trail-encryption-enabled"           = { source = "CLOUD_TRAIL_ENCRYPTION_ENABLED", cis = "3.7" }
    "cmk-backing-key-rotation-enabled"         = { source = "CMK_BACKING_KEY_ROTATION_ENABLED", cis = "3.8" }
    "vpc-flow-logs-enabled"                    = { source = "VPC_FLOW_LOGS_ENABLED", cis = "3.9" }
    "restricted-ssh"                           = { source = "INCOMING_SSH_DISABLED", cis = "5.2" }
    "vpc-default-security-group-closed"        = { source = "VPC_DEFAULT_SECURITY_GROUP_CLOSED", cis = "5.3" }
  }

  # AWS managed rules that cannot be created without parameters
  rule_parameters = {
    "iam-user-unused-credentials-check" = { maxCredentialUsageAge = "90" }
    "access-keys-rotated"               = { maxAccessKeyAge = "90" }
  }
}

resource "aws_iam_role" "config" {
  name = "${var.name_prefix}-config-recorder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "this" {
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = var.include_global_resource_types
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = var.delivery_bucket_name
  s3_key_prefix  = "config"
  depends_on     = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_config_config_rule" "cis" {
  for_each    = local.rules
  name        = "${var.name_prefix}-${each.key}"
  description = "CIS AWS Foundations v1.4 control ${each.value.cis}"

  source {
    owner             = "AWS"
    source_identifier = each.value.source
  }

  input_parameters = contains(keys(local.rule_parameters), each.key) ? jsonencode(local.rule_parameters[each.key]) : null

  tags       = { cis = each.value.cis }
  depends_on = [aws_config_configuration_recorder.this]
}