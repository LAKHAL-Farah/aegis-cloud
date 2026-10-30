variable "ami_id" {
  description = "Run: acct workload ec2 describe-images  and pick any ID LocalStack returns"
  type        = string
  default     = "ami-ff0fea8310f3"
}

module "compute" {
  source                     = "../../modules/compute"
  subnet_id                  = module.network.private_subnet_ids[0]
  security_group_ids         = [module.network.workload_sg_id]
  kms_key_arn                = module.data.kms_key_arn
  ami_id                     = var.ami_id
  enable_detailed_monitoring = false # LocalStack: MonitorInstances not implemented; set true on real AWS
}