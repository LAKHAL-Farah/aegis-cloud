mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"
    }
  }

  mock_resource "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:us-east-1:111111111111:aegis-alerts"
    }
  }
}

variables {
  account_id = "111111111111"
}

run "fifteen_cis_filters_and_alarms_when_a_log_group_is_given" {
  command = plan

  variables {
    log_group_name = "/aegis/cloudtrail/aegis-org-trail"
  }

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.cis) == 15 && length(aws_cloudwatch_metric_alarm.cis) == 15
    error_message = "CIS v1.4.0 section 4 has 15 controls (4.1 to 4.15); each needs a filter AND an alarm."
  }

  assert {
    condition     = alltrue([for a in aws_cloudwatch_metric_alarm.cis : length(a.alarm_actions) == 1])
    error_message = "An alarm with no action is a light nobody sees."
  }

  assert {
    condition     = alltrue([for a in aws_cloudwatch_metric_alarm.cis : strcontains(a.alarm_description, "Runbook: docs/runbooks/")])
    error_message = "Every alarm must name its runbook."
  }

  assert {
    condition     = alltrue([for a in aws_cloudwatch_metric_alarm.cis : startswith(a.alarm_name, "aegis-cis-4_")])
    error_message = "compliance_score.py counts alarms by this name prefix."
  }
}

run "no_cis_resources_without_a_log_group" {
  command = plan

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.cis) == 0 && length(aws_cloudwatch_metric_alarm.cis) == 0
    error_message = "Without a log group there is nothing to filter."
  }
}

run "pipeline_alarms_treat_silence_as_failure" {
  command = plan

  variables {
    pipeline_components = ["detector", "responder"]
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.pipeline) == 2
    error_message = "One alarm per pipeline component."
  }

  assert {
    condition     = alltrue([for a in aws_cloudwatch_metric_alarm.pipeline : a.treat_missing_data == "breaching"])
    error_message = "Missing data must breach, or a dead watchdog looks like a healthy pipeline."
  }

  assert {
    condition     = length(aws_cloudwatch_dashboard.ops) == 1
    error_message = "The ops dashboard exists when there is a pipeline to show."
  }
}

run "alert_topic_is_encrypted_with_a_rotating_key" {
  command = apply

  assert {
    condition     = aws_kms_key.alerts.enable_key_rotation == true && aws_sns_topic.alerts.kms_master_key_id != null
    error_message = "The alert topic must be encrypted with a customer key that rotates (CIS 3.8 spirit)."
  }
}
