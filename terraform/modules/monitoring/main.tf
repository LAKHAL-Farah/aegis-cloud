locals {
  # CIS AWS Foundations Benchmark v1.4.0, section 4 (4.1 to 4.15). Verify numbering and patterns against the PDF you cite.
  # key = control id with the dots replaced by underscores (safe in metric and alarm names)
  cis = {
    "4_01_unauthorized_api_calls" = {
      title   = "4.1 Unauthorized API calls"
      pattern = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    }
    "4_02_console_signin_without_mfa" = {
      title   = "4.2 Console sign-in without MFA"
      pattern = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    }
    "4_03_root_account_usage" = {
      title   = "4.3 Root account usage"
      pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }
    "4_04_iam_policy_changes" = {
      title   = "4.4 IAM policy changes"
      pattern = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"
    }
    "4_05_cloudtrail_config_changes" = {
      title   = "4.5 CloudTrail configuration changes"
      pattern = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    }
    "4_06_console_auth_failures" = {
      title   = "4.6 Console authentication failures"
      pattern = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    }
    "4_07_cmk_disable_or_deletion" = {
      title   = "4.7 CMK disabled or scheduled for deletion"
      pattern = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    }
    "4_08_s3_bucket_policy_changes" = {
      title   = "4.8 S3 bucket policy changes"
      pattern = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
    }
    "4_09_config_changes" = {
      title   = "4.9 AWS Config configuration changes"
      pattern = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
    }
    "4_10_security_group_changes" = {
      title   = "4.10 Security group changes"
      pattern = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
    }
    "4_11_nacl_changes" = {
      title   = "4.11 Network ACL changes"
      pattern = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    }
    "4_12_network_gateway_changes" = {
      title   = "4.12 Network gateway changes"
      pattern = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    }
    "4_13_route_table_changes" = {
      title   = "4.13 Route table changes"
      pattern = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
    }
    "4_14_vpc_changes" = {
      title   = "4.14 VPC changes"
      pattern = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
    }
    "4_15_organizations_changes" = {
      title   = "4.15 AWS Organizations changes"
      pattern = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) || ($.eventName = CreateAccount) || ($.eventName = CreateOrganizationalUnit) || ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) || ($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) || ($.eventName = DeletePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) || ($.eventName = LeaveOrganization) || ($.eventName = MoveAccount) || ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdatePolicy) || ($.eventName = UpdateOrganizationalUnit)) }"
    }
  }

  cis_enabled = var.log_group_name == null ? {} : local.cis
  components  = toset(var.pipeline_components)
}

# ---------- alert channel: a topic encrypted with our own key ----------
# The AWS-managed SNS key cannot be used by CloudWatch alarms, so the key is ours and its policy names CloudWatch.

resource "aws_kms_key" "alerts" {
  #checkov:skip=CKV_AWS_109:Key policies must use Resource "*" (it means "this key") and delegate to IAM via the account root
  #checkov:skip=CKV_AWS_111:Same: key-policy statements apply to this key only
  #checkov:skip=CKV_AWS_356:Same: Resource "*" in a key policy is the key itself
  description             = "AegisCloud alert topic key (${var.account_id})"
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
        Sid       = "AllowCloudWatchAlarmsToPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
      },
    ]
  })
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = aws_kms_key.alerts.arn
}

# ---------- CIS section 4: one metric filter and one alarm per control ----------

resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each       = local.cis_enabled
  name           = "${var.name_prefix}-cis-${each.key}"
  log_group_name = var.log_group_name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.key
    namespace = "Aegis/CIS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each            = local.cis_enabled
  alarm_name          = "${var.name_prefix}-cis-${each.key}"
  alarm_description   = "CIS ${each.value.title}. Runbook: ${var.runbook_dir}/cis-alarm.md"
  namespace           = "Aegis/CIS"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.cis]
}

# ---------- the pipeline's own heartbeat ----------
# Missing data BREACHES: if the watchdog itself dies, nothing is published and this alarm fires (dead-man's switch).

resource "aws_cloudwatch_metric_alarm" "pipeline" {
  for_each            = local.components
  alarm_name          = "${var.name_prefix}-pipeline-${each.key}-down"
  alarm_description   = "${each.key} is down, or the watchdog stopped reporting. Runbook: ${var.runbook_dir}/${each.key}-down.md"
  namespace           = "Aegis/Pipeline"
  metric_name         = "ComponentUp"
  dimensions          = { Component = each.key }
  statistic           = "Minimum"
  period              = var.pipeline_period_s
  evaluation_periods  = var.pipeline_evaluation_periods
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_dashboard" "ops" {
  count          = length(var.pipeline_components) > 0 ? 1 : 0
  dashboard_name = "${var.name_prefix}-ops"
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Pipeline components up (1 = up)"
          region  = var.region
          stat    = "Minimum"
          period  = var.pipeline_period_s
          metrics = [for c in var.pipeline_components : ["Aegis/Pipeline", "ComponentUp", "Component", c]]
        }
      },
      {
        type   = "alarm"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Pipeline alarms"
          alarms = [for a in aws_cloudwatch_metric_alarm.pipeline : a.arn]
        }
      },
    ]
  })
}
