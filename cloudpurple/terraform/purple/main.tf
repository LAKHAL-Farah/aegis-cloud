variable "ami_id" {
  type    = string
  default = "ami-03cf127a"
}

module "target" {
  source     = "../modules/range-target"
  name       = "purple"
  account_id = var.accounts[var.account_name]
  hardened   = false
  ami_id     = var.ami_id
}

output "target" {
  value     = module.target.target
  sensitive = true
}