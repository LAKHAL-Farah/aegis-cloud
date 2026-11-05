output "archive_bucket_name" {
  value = var.create_log_archive ? local.archive_bucket_name : null
}

output "kms_key_arn" {
  value = var.create_log_archive ? aws_kms_key.archive[0].arn : null
}

output "trail_arn" {
  value = var.create_trail ? aws_cloudtrail.main[0].arn : null
}

output "log_group_name" {
  description = "CloudWatch Logs group that receives the trail (null unless enable_cloudwatch_logs)"
  value       = local.cwl_enabled ? aws_cloudwatch_log_group.trail[0].name : null
}
