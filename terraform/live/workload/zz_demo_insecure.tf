# DEMO ONLY: this file exists on a throwaway branch to prove the CI gates block insecure code.
# NEVER merge it.

resource "aws_s3_bucket" "oops" {
  bucket = "aegis-oops-public-${var.accounts[var.account_name]}"
}

resource "aws_s3_bucket_ownership_controls" "oops" {
  bucket = aws_s3_bucket.oops.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "oops" {
  bucket                  = aws_s3_bucket.oops.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "oops" {
  bucket     = aws_s3_bucket.oops.id
  acl        = "public-read"
  depends_on = [aws_s3_bucket_ownership_controls.oops, aws_s3_bucket_public_access_block.oops]
}

resource "aws_vpc_security_group_ingress_rule" "oops_ssh" {
  security_group_id = module.network.workload_sg_id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}