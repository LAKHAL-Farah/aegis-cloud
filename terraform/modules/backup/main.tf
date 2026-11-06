# AWS Backup: a vault, a daily plan, a selection. On LocalStack this is a stored definition only: the restore the
# project actually proves is `make ops-drill` (S3 versioning), see ADR-0017.

resource "aws_kms_key" "vault" {
  #checkov:skip=CKV_AWS_109:Key policies must use Resource "*" (it means "this key") and delegate to IAM via the account root
  #checkov:skip=CKV_AWS_111:Same: key-policy statements apply to this key only
  #checkov:skip=CKV_AWS_356:Same: Resource "*" in a key policy is the key itself
  description             = "AegisCloud backup vault key"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnableRootPermissions"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_backup_vault" "this" {
  name        = "${var.name_prefix}-vault"
  kms_key_arn = aws_kms_key.vault.arn
}

resource "aws_backup_plan" "daily" {
  name = "${var.name_prefix}-daily"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.this.name
    schedule          = var.schedule
    start_window      = 60
    completion_window = 180

    lifecycle {
      delete_after = var.retention_days
    }
  }
}

resource "aws_iam_role" "backup" {
  name = "${var.name_prefix}-backup"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = toset([
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
    "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore",
  ])
  role       = aws_iam_role.backup.name
  policy_arn = each.value
}

resource "aws_backup_selection" "this" {
  count        = length(var.resource_arns) > 0 ? 1 : 0
  name         = "${var.name_prefix}-selection"
  plan_id      = aws_backup_plan.daily.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = var.resource_arns
}
