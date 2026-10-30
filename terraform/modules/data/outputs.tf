output "kms_key_arn" {
  value = aws_kms_key.data.arn
}

output "data_bucket_name" {
  value = local.data_bucket
}