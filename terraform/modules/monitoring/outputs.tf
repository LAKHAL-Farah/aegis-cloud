output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "cis_alarm_names" {
  value = sort([for a in aws_cloudwatch_metric_alarm.cis : a.alarm_name])
}

output "pipeline_alarm_names" {
  value = sort([for a in aws_cloudwatch_metric_alarm.pipeline : a.alarm_name])
}
