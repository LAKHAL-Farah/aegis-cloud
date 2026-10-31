variable "name" {
  description = "purple | hardened (used in resource names)"
  type        = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "hardened" {
  description = "false = deliberately vulnerable twin, true = hardened twin"
  type        = bool
}

variable "permissions_boundary_arn" {
  description = "Boundary attached to the attacker-controlled users (hardened twin only)"
  type        = string
  default     = null
}

variable "create_instance" {
  type    = bool
  default = true
}

variable "ami_id" {
  description = "A LocalStack AMI: acct <account> ec2 describe-images"
  type        = string
  default     = "ami-03cf127a"
}