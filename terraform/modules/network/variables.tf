variable "name_prefix" {
  type    = string
  default = "aegis"
}

variable "account_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "azs" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
}

variable "enable_nat" {
  description = "NAT gateway for the private tier. Off by default (cost on real AWS; endpoints cover SSM/KMS/S3)."
  type        = bool
  default     = false
}

variable "enable_interface_endpoints" {
  description = "Create interface endpoints (SSM, KMS, logs). Set false if LocalStack rejects them."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  type    = number
  default = 365
}