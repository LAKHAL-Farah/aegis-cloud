module "network" {
  source     = "../../modules/network"
  account_id = var.accounts[var.account_name]
  region     = var.region
}