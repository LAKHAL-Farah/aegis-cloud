# PROBE 4: GuardDuty    PROBE 5: Security Hub
resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:${local.partition}:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
  depends_on    = [aws_securityhub_account.main]
}
