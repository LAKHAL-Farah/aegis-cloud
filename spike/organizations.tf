# PROBE 1: Organizations + SCP
resource "aws_organizations_organization" "this" {
  feature_set                   = "ALL"
  enabled_policy_types          = ["SERVICE_CONTROL_POLICY"]
  aws_service_access_principals = ["cloudtrail.amazonaws.com", "config.amazonaws.com"]
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "workloads"
  parent_id = aws_organizations_organization.this.roots[0].id
}

resource "aws_organizations_policy" "protect_security_services" {
  name        = "aegis-protect-security-services"
  description = "Deny tampering with CloudTrail, Config and GuardDuty"
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenySecurityTampering"
      Effect = "Deny"
      Action = [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "config:StopConfigurationRecorder",
        "config:DeleteConfigurationRecorder",
        "guardduty:DeleteDetector",
        "organizations:LeaveOrganization"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_organizations_policy_attachment" "workloads" {
  policy_id = aws_organizations_policy.protect_security_services.id
  target_id = aws_organizations_organizational_unit.workloads.id
}
