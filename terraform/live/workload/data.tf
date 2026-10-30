module "data" {
  source     = "../../modules/data"
  account_id = var.accounts[var.account_name]
  region     = var.region
}