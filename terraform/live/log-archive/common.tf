terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "account_name" {
  description = "Key into var.accounts: management | log_archive | security | workload"
  type        = string
}

variable "accounts" {
  description = "Account name -> 12-digit ID (on LocalStack the access key becomes the account ID)"
  type        = map(string)
}

variable "localstack_endpoint" {
  type    = string
  default = "http://localhost:4566"
}

variable "offline" {
  description = "CI mode: plan without any reachable AWS/LocalStack (skips the account-ID lookup)"
  type        = bool
  default     = false
}

provider "aws" {
  region     = var.region
  access_key = var.accounts[var.account_name]
  secret_key = "test"

  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = var.offline

  endpoints {
    apigateway     = var.localstack_endpoint
    cloudformation = var.localstack_endpoint
    cloudtrail     = var.localstack_endpoint
    cloudwatch     = var.localstack_endpoint
    cloudwatchlogs = var.localstack_endpoint
    configservice  = var.localstack_endpoint
    ec2            = var.localstack_endpoint
    eventbridge    = var.localstack_endpoint
    iam            = var.localstack_endpoint
    kms            = var.localstack_endpoint
    lambda         = var.localstack_endpoint
    organizations  = var.localstack_endpoint
    s3             = var.localstack_endpoint
    secretsmanager = var.localstack_endpoint
    sns            = var.localstack_endpoint
    sqs            = var.localstack_endpoint
    ssm            = var.localstack_endpoint
    sts            = var.localstack_endpoint
  }

  default_tags {
    tags = {
      Project   = "aegiscloud"
      ManagedBy = "terraform"
      Account   = var.account_name
    }
  }
}