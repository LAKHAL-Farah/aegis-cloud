output "archive_bucket_name" {
  value = module.logging.archive_bucket_name
}

output "kms_key_arn" {
  value = module.logging.kms_key_arn
}