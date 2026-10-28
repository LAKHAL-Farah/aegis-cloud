terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

variable "localstack_endpoint" {
  type    = string
  default = "http://localhost:4566"
}

provider "aws" {
  region     = "us-east-1"
  access_key = "test" # a 12-digit value here would become the LocalStack account ID
  secret_key = "test"

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  s3_use_path_style           = true

  endpoints {
    organizations = var.localstack_endpoint
    iam           = var.localstack_endpoint
    sts           = var.localstack_endpoint
    s3            = var.localstack_endpoint
    cloudtrail    = var.localstack_endpoint
    configservice = var.localstack_endpoint
    guardduty     = var.localstack_endpoint
    securityhub   = var.localstack_endpoint
    events        = var.localstack_endpoint
    sqs           = var.localstack_endpoint
    sns           = var.localstack_endpoint
    kms           = var.localstack_endpoint
    lambda        = var.localstack_endpoint
    ssm           = var.localstack_endpoint
    ec2           = var.localstack_endpoint
    cloudwatch    = var.localstack_endpoint
    logs          = var.localstack_endpoint
    backup        = var.localstack_endpoint
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
