variable "name_prefix" {
  type    = string
  default = "aegis"
}

variable "account_id" {
  description = "Account that trusts these roles (principals in this account may assume them)"
  type        = string
}