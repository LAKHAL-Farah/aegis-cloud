variable "name_prefix" {
  type    = string
  default = "aegis"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "log_archive_account_id" {
  type = string
}

variable "management_account_id" {
  type = string
}

variable "source_account_ids" {
  description = "Accounts allowed to deliver AWS Config data into the archive"
  type        = list(string)
  default     = []
}

variable "trail_name" {
  type    = string
  default = "aegis-org-trail"
}

variable "create_log_archive" {
  description = "Create the bucket + KMS key (run in the log_archive account)"
  type        = bool
  default     = false
}

variable "create_trail" {
  description = "Create the CloudTrail (run in the management account)"
  type        = bool
  default     = false
}

variable "is_organization_trail" {
  description = "true = one trail for all org accounts. Set false if LocalStack rejects it (see troubleshooting)."
  type        = bool
  default     = true
}

variable "log_bucket_name" {
  description = "Trail destination bucket (only used when create_trail = true)"
  type        = string
  default     = null
}

variable "kms_key_arn" {
  description = "Key that encrypts the trail (only used when create_trail = true)"
  type        = string
  default     = null
}