variable "name_prefix" {
  type    = string
  default = "aegis"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "account_id" {
  description = "Account this module runs in (the alerts key trusts its root)"
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch Logs group that receives CloudTrail. null = no CIS section 4 filters and alarms"
  type        = string
  default     = null
}

variable "pipeline_components" {
  description = "Components whose Aegis/Pipeline ComponentUp heartbeat is alarmed on (published by `ops.py watchdog --publish`). Empty = none"
  type        = list(string)
  default     = []
}

variable "pipeline_period_s" {
  description = "Seconds per datapoint. The watchdog publishes every few seconds, so 60 is the CloudWatch standard resolution"
  type        = number
  default     = 60
}

variable "pipeline_evaluation_periods" {
  description = "Consecutive bad periods before a pipeline alarm fires (3 x 60 s = a component has been down for three minutes)"
  type        = number
  default     = 3
}

variable "runbook_dir" {
  description = "Where the runbooks live, quoted in every alarm description"
  type        = string
  default     = "docs/runbooks"
}
