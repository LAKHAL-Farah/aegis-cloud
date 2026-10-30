variable "name_prefix" {
  type    = string
  default = "aegis"
}

variable "delivery_bucket_name" {
  description = "Bucket (in the log-archive account) that receives Config snapshots under the config/ prefix"
  type        = string
}

variable "include_global_resource_types" {
  description = "Record IAM and other global resources (CIS 3.5: at least one region must)"
  type        = bool
  default     = true
}