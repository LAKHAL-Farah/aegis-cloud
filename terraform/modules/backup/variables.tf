variable "name_prefix" {
  type    = string
  default = "aegis"
}

variable "account_id" {
  type = string
}

variable "resource_arns" {
  description = "What to back up (S3 buckets must have versioning on). Empty = vault and plan only"
  type        = list(string)
  default     = []
}

variable "schedule" {
  description = "Backup schedule (cron, UTC)"
  type        = string
  default     = "cron(0 3 * * ? *)"
}

variable "retention_days" {
  type    = number
  default = 35
}
