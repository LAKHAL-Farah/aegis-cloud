module "logging" {
  source = "../../modules/logging"

  region                 = var.region
  log_archive_account_id = var.accounts["log_archive"]
  management_account_id  = var.accounts["management"]
  source_account_ids     = values(var.accounts)

  create_log_archive = true
  create_trail       = false
}