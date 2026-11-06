variable "name_prefix" {
  type    = string
  default = "aegis"
}

variable "patch_group" {
  description = "Value of the `Patch Group` tag on the instances this baseline governs"
  type        = string
  default     = "aegis-workload"
}

variable "operating_system" {
  type    = string
  default = "AMAZON_LINUX_2023"
}

variable "schedule" {
  description = "Maintenance window schedule (cron, UTC). Weekly, Sunday 04:00"
  type        = string
  default     = "cron(0 4 ? * SUN *)"
}

variable "approve_after_days" {
  description = "Days to wait after a patch is released before approving it"
  type        = number
  default     = 7
}
