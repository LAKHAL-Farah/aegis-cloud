module "iam_baseline" {
  source     = "../../modules/iam-baseline"
  account_id = var.accounts[var.account_name]
}

module "config_rules" {
  source               = "../../modules/config-rules"
  delivery_bucket_name = "aegis-log-archive-${var.accounts["log_archive"]}"
}