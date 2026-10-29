variable "bucket_name" {
  description = "Globally unique bucket name"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for SSE-KMS. null = SSE-S3 (AES256), used only for the access-log sink"
  type        = string
  default     = null
}

variable "logging_target_bucket" {
  description = "Bucket that receives S3 server-access logs for this bucket (same account/region). null = no logging"
  type        = string
  default     = null
}

variable "logging_target_prefix" {
  type    = string
  default = "s3-access/"
}

variable "versioning_enabled" {
  type    = bool
  default = true
}

variable "transition_to_glacier_days" {
  type    = number
  default = 90
}

variable "expiration_days" {
  type    = number
  default = 365
}

variable "force_destroy" {
  description = "Lab setting: lets terraform destroy remove non-empty buckets. Set false on real AWS."
  type        = bool
  default     = true
}

variable "extra_policy_statements" {
  description = "Additional bucket-policy statements (a list of objects with differing shapes, so type = any, JSON-encoded as-is)"
  type        = any
  default     = []
}

variable "tags" {
  type    = map(string)
  default = {}
}