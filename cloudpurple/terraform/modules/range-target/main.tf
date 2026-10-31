# DELIBERATELY VULNERABLE when hardened = false. Lives outside terraform/live/ so
# the Stage 1 gates never scan it (ADR-0006). All data is synthetic.

locals {
  data_bucket  = "${var.name}-data-${var.account_id}"
  trail_bucket = "${var.name}-trail-${var.account_id}"
  seed_keys    = [for i in range(1, 13) : format("customers/record-%02d.csv", i)]
  pab_flag     = var.hardened
  intern_arn   = "arn:aws:iam::${var.account_id}:policy/intern-policy"
}

# ---------------------------------------------------------------- data + key
resource "aws_kms_key" "data" {
  description             = "${var.name} data key"
  enable_key_rotation     = var.hardened
  deletion_window_in_days = 7
}

resource "aws_s3_bucket" "data" {
  bucket        = local.data_bucket
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    object_ownership = "BucketOwnerPreferred" # ACLs allowed: S07 needs this
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = local.pab_flag
  block_public_policy     = local.pab_flag
  ignore_public_acls      = local.pab_flag
  restrict_public_buckets = local.pab_flag
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  count  = var.hardened ? 1 : 0
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_s3_object" "seed" {
  for_each   = toset(local.seed_keys)
  bucket     = aws_s3_bucket.data.id
  key        = each.key
  content    = "synthetic customer record ${each.key}" # run_attacks cleanup re-creates this exact text
  depends_on = [aws_s3_bucket_versioning.data, aws_s3_bucket_server_side_encryption_configuration.data]
}

resource "aws_secretsmanager_secret" "db" {
  name                    = "${var.name}/db-password"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = "synthetic-not-a-real-password"
}

# ---------------------------------------------------------------- identities
resource "aws_iam_user" "dev_svc" {
  name                 = "dev-svc"
  permissions_boundary = var.permissions_boundary_arn
  force_destroy        = true
}

resource "aws_iam_access_key" "dev_svc" {
  user = aws_iam_user.dev_svc.name
}

# The classic mistake: a service user with Allow * on *.
resource "aws_iam_user_policy" "dev_svc" {
  name = "dev-svc-wildcard"
  user = aws_iam_user.dev_svc.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_policy" "intern" {
  name = "intern-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Basics"
        Effect   = "Allow"
        Action   = ["s3:ListAllMyBuckets"]
        Resource = "*"
      },
      {
        Sid      = "EditOwnPolicy" # the privilege-escalation path S09 walks
        Effect   = "Allow"
        Action   = ["iam:CreatePolicyVersion", "iam:ListPolicyVersions", "iam:SetDefaultPolicyVersion"]
        Resource = local.intern_arn
      },
    ]
  })
}

resource "aws_iam_user" "intern" {
  name                 = "intern"
  permissions_boundary = var.permissions_boundary_arn
  force_destroy        = true
}

resource "aws_iam_user_policy_attachment" "intern" {
  user       = aws_iam_user.intern.name
  policy_arn = aws_iam_policy.intern.arn
}

resource "aws_iam_access_key" "intern" {
  user = aws_iam_user.intern.name
}

# ---------------------------------------------------------------- audit trail (local to this account)
resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "Write"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${var.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudtrail" "this" {
  name                          = "${var.name}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = var.hardened
  enable_log_file_validation    = var.hardened
  enable_logging                = true

  # S3 data events (GetObject...) for the purple twin. The hardened twin sits under the
  # protect-logging SCP, which denies cloudtrail:PutEventSelectors: our own guardrail blocks us.
  dynamic "event_selector" {
    for_each = var.hardened ? [] : [1]
    content {
      read_write_type           = "All"
      include_management_events = true
      data_resource {
        type   = "AWS::S3::Object"
        values = ["${aws_s3_bucket.data.arn}/"]
      }
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}

# ---------------------------------------------------------------- network + instance
resource "aws_vpc" "this" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name}-vpc" }
}

resource "aws_subnet" "this" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.50.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = !var.hardened
  tags                    = { Name = "${var.name}-subnet" }
}

resource "aws_internet_gateway" "this" {
  count  = var.hardened ? 0 : 1
  vpc_id = aws_vpc.this.id
}

# Victim SG: starts CLOSED in both twins. S05 opens it.
resource "aws_security_group" "victim" {
  name        = "${var.name}-victim"
  description = "Closed security group that scenario S05 tries to open"
  vpc_id      = aws_vpc.this.id
}

# Standing misconfiguration, purple only: SSH open to the world.
resource "aws_security_group" "legacy_open" {
  count       = var.hardened ? 0 : 1
  name        = "${var.name}-legacy-open"
  description = "Legacy rule nobody cleaned up"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "ssh from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  count                       = var.create_instance ? 1 : 0
  ami                         = var.ami_id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.this.id
  vpc_security_group_ids      = var.hardened ? [aws_security_group.victim.id] : aws_security_group.legacy_open[*].id
  associate_public_ip_address = !var.hardened

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = var.hardened ? "required" : "optional" # optional = IMDSv1 allowed
  }

  root_block_device {
    encrypted   = var.hardened
    volume_type = "gp3"
    volume_size = 8
  }

  tags = { Name = "${var.name}-app-1" }
}