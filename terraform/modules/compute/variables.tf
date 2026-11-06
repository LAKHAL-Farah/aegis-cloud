variable "name_prefix" {
  type    = string
  default = "aegis"
}

variable "subnet_id" {
  type = string
}

variable "security_group_ids" {
  type = list(string)
}

variable "kms_key_arn" {
  description = "Key for the root EBS volume"
  type        = string
}

variable "ami_id" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}



variable "enable_detailed_monitoring" {
  description = "EC2 detailed monitoring (CIS/Checkov want it on). LocalStack lacks MonitorInstances, so the lab root sets false."
  type        = bool
  default     = true
}

variable "patch_group" {
  description = "Value of the `Patch Group` tag. Must match the patching module's patch_group"
  type        = string
  default     = "aegis-workload"
}
