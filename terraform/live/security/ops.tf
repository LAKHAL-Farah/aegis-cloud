# Pipeline health: the watchdog (`make ops-watchdog`) publishes Aegis/Pipeline ComponentUp here; silence also alarms.
# `localstack` is not alarmed: on LocalStack the metric would be published to the thing that is down.
module "monitoring" {
  source              = "../../modules/monitoring"
  region              = var.region
  account_id          = var.accounts[var.account_name]
  pipeline_components = ["detector", "responder"]
}
