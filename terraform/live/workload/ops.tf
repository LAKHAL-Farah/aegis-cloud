# Stage 5 operations. Backup and patching are toggles (ADR-0004 pattern): the definitions are portable to real AWS,
# but LocalStack does not implement every call the provider makes. Measured on LocalStack (docs/localstack-limitations.md):
#   enable_backup   = true  applies cleanly (definitions only: no backup job ever runs)
#   enable_patching = true  FAILS (CreatePatchBaseline InvalidResourceId; maintenance window target read "empty result")
#   terraform -chdir=terraform/live/workload apply -var enable_backup=true
variable "enable_backup" {
  description = "AWS Backup vault, daily plan and selection for the data bucket"
  type        = bool
  default     = false
}

variable "enable_patching" {
  description = "SSM Patch Manager baseline, patch group, maintenance window and task"
  type        = bool
  default     = false
}

module "backup" {
  count         = var.enable_backup ? 1 : 0
  source        = "../../modules/backup"
  account_id    = var.accounts[var.account_name]
  resource_arns = ["arn:aws:s3:::${module.data.data_bucket_name}"]
}

module "patching" {
  count  = var.enable_patching ? 1 : 0
  source = "../../modules/patching"
}
