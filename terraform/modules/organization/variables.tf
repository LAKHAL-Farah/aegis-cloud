variable "scp_dir" {
  description = "Directory containing SCP *.json files. null = <repo>/policies/scp"
  type        = string
  default     = null
}

variable "ou_scps" {
  description = "OU name -> list of SCP names (file name without .json) attached to it"
  type        = map(list(string))
  default = {
    security  = ["protect-logging", "deny-leave-org"]
    workloads = ["protect-logging", "deny-leave-org", "region-lock", "deny-public-s3-acls"]
  }
}

variable "create_member_accounts" {
  description = "Create member accounts through Organizations (see section 7: IDs may not match your 12-digit keys on LocalStack)"
  type        = bool
  default     = false
}

variable "member_accounts" {
  type = map(object({
    email = string
    ou    = string
  }))
  default = {}
}