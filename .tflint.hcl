config {
  call_module_type = "local"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "aws" {
  enabled = true
  version = "0.38.0" # bump to the latest release of tflint-ruleset-aws when `tflint --init` says so
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# Roots (terraform/live/*) legitimately have no variables.tf/outputs.tf split.
rule "terraform_standard_module_structure" {
  enabled = false
}