variable "use_org_trail" {
  description = "true = organization-wide trail. If LocalStack rejects it, set false in terraform.tfvars and note it in localstack-limitations.md"
  type        = bool
  default     = true
}

module "organization" {
  source = "../../modules/organization"
}

data "terraform_remote_state" "log_archive" {
  count   = var.offline ? 0 : 1
  backend = "s3"
  config = {
    bucket                      = "aegis-tfstate"
    key                         = "log-archive/terraform.tfstate"
    region                      = "us-east-1"
    access_key                  = "test"
    secret_key                  = "test"
    endpoints                   = { s3 = var.localstack_endpoint }
    use_path_style              = true
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_requesting_account_id  = true
    skip_region_validation      = true
  }
}

locals {
  log_bucket = try(data.terraform_remote_state.log_archive[0].outputs.archive_bucket_name, "offline-placeholder")
  log_kms    = try(data.terraform_remote_state.log_archive[0].outputs.kms_key_arn, "arn:aws:kms:us-east-1:222222222222:key/offline-placeholder")
}

module "trail" {
  source = "../../modules/logging"

  region                 = var.region
  log_archive_account_id = var.accounts["log_archive"]
  management_account_id  = var.accounts["management"]

  create_log_archive    = false
  create_trail          = true
  is_organization_trail = var.use_org_trail
  log_bucket_name       = local.log_bucket
  kms_key_arn           = local.log_kms

  depends_on = [module.organization]
}