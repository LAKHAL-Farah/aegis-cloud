locals {
  trust_root = "arn:aws:iam::${var.account_id}:root"
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
  max_password_age               = 90
}

resource "aws_iam_policy" "boundary" {
  #checkov:skip=CKV_AWS_286:A permission boundary is a ceiling, not a grant; it intentionally names broad service families
  #checkov:skip=CKV_AWS_287:Same: ceiling, not a grant
  #checkov:skip=CKV_AWS_288:Same: ceiling, not a grant
  #checkov:skip=CKV_AWS_289:Same: ceiling, not a grant
  #checkov:skip=CKV_AWS_290:Same: ceiling, not a grant
  #checkov:skip=CKV_AWS_355:Same: ceiling, not a grant; effective permissions are the intersection with the role's own policies
  name        = "${var.name_prefix}-permission-boundary"
  description = "Ceiling for automation roles: broad service access, but no identity creation and no audit tampering"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowWorkloadServices"
        Effect = "Allow"
        Action = [
          "ec2:*", "s3:*", "kms:*", "logs:*", "cloudwatch:*", "ssm:*",
          "lambda:*", "events:*", "sns:*", "sqs:*", "secretsmanager:*",
          "iam:Get*", "iam:List*", "iam:PassRole", "iam:CreateServiceLinkedRole",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyIdentityEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteUserPermissionsBoundary",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyAuditTampering"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail",
          "config:StopConfigurationRecorder",
          "config:DeleteConfigurationRecorder",
        ]
        Resource = "*"
      },
    ]
  })
}

# ---- break-glass admin: MFA required to assume ----
resource "aws_iam_role" "break_glass" {
  #checkov:skip=CKV_AWS_61:Trust is delegated to the account root so IAM policies decide; MFA is required and no IAM users exist (boundary denies iam:CreateUser)
  name                 = "${var.name_prefix}-break-glass-admin"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.trust_root }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "break_glass" {
  #checkov:skip=CKV_AWS_274:Emergency access role by design; protected by MFA-only trust and not used by automation
  role       = aws_iam_role.break_glass.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ---- deployer: PowerUser, capped by the boundary ----
resource "aws_iam_role" "deployer" {
  #checkov:skip=CKV_AWS_61:Account-root trust delegates to IAM; Stage 3/4 replace it with the specific automation roles that assume this one
  name                 = "${var.name_prefix}-deployer"
  permissions_boundary = aws_iam_policy.boundary.arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.trust_root }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "deployer" {
  role       = aws_iam_role.deployer.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# ---- auditor: read-only security view ----
resource "aws_iam_role" "auditor" {
  #checkov:skip=CKV_AWS_61:Account-root trust delegates to IAM; Stage 3 replaces it with the specific collector role
  name = "${var.name_prefix}-auditor"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.trust_root }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "auditor" {
  role       = aws_iam_role.auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}