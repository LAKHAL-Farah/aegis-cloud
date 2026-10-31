# One sensitive object. export_targets.py turns it into build/range/targets.json for the runner.
output "target" {
  sensitive = true
  value = {
    name       = var.name
    account_id = var.account_id
    hardened   = var.hardened
    resources = {
      data_bucket       = aws_s3_bucket.data.id
      trail_name        = aws_cloudtrail.this.name
      trail_bucket      = aws_s3_bucket.trail.id
      victim_sg_id      = aws_security_group.victim.id
      kms_key_id        = aws_kms_key.data.key_id
      secret_name       = aws_secretsmanager_secret.db.name
      intern_policy_arn = aws_iam_policy.intern.arn
      dev_user          = aws_iam_user.dev_svc.name
      intern_user       = aws_iam_user.intern.name
      instance_id       = one(aws_instance.app[*].id)
    }
    credentials = {
      attacker_key_id = aws_iam_access_key.dev_svc.id
      attacker_secret = aws_iam_access_key.dev_svc.secret
      intern_key_id   = aws_iam_access_key.intern.id
      intern_secret   = aws_iam_access_key.intern.secret
    }
  }
}