locals {
  tiers = { public = 0, private = 10, isolated = 20 }

  # {"public-0" = {tier, az, cidr}, "public-1" = ..., "private-0" = ..., ...}
  subnets = merge([
    for tier, base in local.tiers : {
      for i, az in var.azs : "${tier}-${i}" => {
        tier = tier
        az   = az
        cidr = cidrsubnet(var.cidr, 8, base + i)
      }
    }
  ]...)

  nacl_rules = {
    public = [
      { n = 90, egress = false, proto = "tcp", from = 22, to = 22, cidr = "0.0.0.0/0", action = "deny" },
      { n = 91, egress = false, proto = "tcp", from = 3389, to = 3389, cidr = "0.0.0.0/0", action = "deny" },
      { n = 100, egress = false, proto = "tcp", from = 443, to = 443, cidr = "0.0.0.0/0", action = "allow" },
      { n = 110, egress = false, proto = "tcp", from = 80, to = 80, cidr = "0.0.0.0/0", action = "allow" },
      { n = 120, egress = false, proto = "tcp", from = 1024, to = 3388, cidr = "0.0.0.0/0", action = "allow" },
      { n = 121, egress = false, proto = "tcp", from = 3390, to = 65535, cidr = "0.0.0.0/0", action = "allow" },
      { n = 100, egress = true, proto = "-1", from = 0, to = 0, cidr = "0.0.0.0/0", action = "allow" },
    ]
    private = [
      { n = 100, egress = false, proto = "-1", from = 0, to = 0, cidr = var.cidr, action = "allow" },
      { n = 120, egress = false, proto = "tcp", from = 1024, to = 3388, cidr = "0.0.0.0/0", action = "allow" },
      { n = 121, egress = false, proto = "tcp", from = 3390, to = 65535, cidr = "0.0.0.0/0", action = "allow" },
      { n = 100, egress = true, proto = "tcp", from = 443, to = 443, cidr = "0.0.0.0/0", action = "allow" },
      { n = 110, egress = true, proto = "-1", from = 0, to = 0, cidr = var.cidr, action = "allow" },
    ]
    isolated = [
      { n = 100, egress = false, proto = "-1", from = 0, to = 0, cidr = var.cidr, action = "allow" },
      { n = 100, egress = true, proto = "-1", from = 0, to = 0, cidr = var.cidr, action = "allow" },
    ]
  }

  nacl_rule_map = merge([
    for tier, rules in local.nacl_rules : {
      for r in rules : "${tier}-${r.egress ? "out" : "in"}-${r.n}" => merge(r, { tier = tier })
    }
  ]...)

  interface_endpoints = var.enable_interface_endpoints ? toset(["ssm", "ssmmessages", "ec2messages", "logs", "kms"]) : toset([])
  private_subnet_ids  = [for k, s in aws_subnet.this : s.id if local.subnets[k].tier == "private"]
}

# ---------------- core ----------------

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "this" {
  for_each                = local.subnets
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value.az
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = false # no auto public IPs, even in the public tier
  tags                    = { Name = "${var.name_prefix}-${each.key}", Tier = each.value.tier }
}

resource "aws_route_table" "this" {
  for_each = local.tiers
  vpc_id   = aws_vpc.this.id
  tags     = { Name = "${var.name_prefix}-${each.key}", Tier = each.key }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.this["public"].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "this" {
  for_each       = local.subnets
  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = aws_route_table.this[each.value.tier].id
}

resource "aws_eip" "nat" {
  count  = var.enable_nat ? 1 : 0
  domain = "vpc"
}

resource "aws_nat_gateway" "this" {
  count         = var.enable_nat ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.this["public-0"].id
}

resource "aws_route" "private_nat" {
  count                  = var.enable_nat ? 1 : 0
  route_table_id         = aws_route_table.this["private"].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[0].id
}

# ---------------- NACLs ----------------

resource "aws_network_acl" "this" {
  for_each   = local.tiers
  vpc_id     = aws_vpc.this.id
  subnet_ids = [for k, s in aws_subnet.this : s.id if local.subnets[k].tier == each.key]
  tags       = { Name = "${var.name_prefix}-${each.key}" }
}

resource "aws_network_acl_rule" "this" {
  for_each       = local.nacl_rule_map
  network_acl_id = aws_network_acl.this[each.value.tier].id
  rule_number    = each.value.n
  egress         = each.value.egress
  protocol       = each.value.proto
  rule_action    = each.value.action
  cidr_block     = each.value.cidr
  from_port      = each.value.proto == "-1" ? null : each.value.from
  to_port        = each.value.proto == "-1" ? null : each.value.to
}

# ---------------- security groups ----------------

# CIS 5.3: the default SG allows nothing. Declaring it with no rules *removes* the default allow-all.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name_prefix}-default-closed" }
}

resource "aws_security_group" "workload" {
  #checkov:skip=CKV2_AWS_5:Attached to the app instance in the workload root (compute.tf, Week 3); Checkov cannot trace attachments across module boundaries
  name        = "${var.name_prefix}-workload"
  description = "Private workloads: no inbound, HTTPS outbound only"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name_prefix}-workload" }
}

resource "aws_vpc_security_group_egress_rule" "workload_https" {
  security_group_id = aws_security_group.workload.id
  description       = "HTTPS out (SSM, KMS, S3 via endpoints)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name_prefix}-endpoints"
  description = "Interface VPC endpoints: HTTPS from inside the VPC only"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name_prefix}-endpoints" }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from the VPC"
  cidr_ipv4         = var.cidr
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# ---------------- VPC endpoints ----------------

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.this["private"].id, aws_route_table.this["isolated"].id]
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}

# ---------------- flow logs (CIS 3.9) ----------------

resource "aws_kms_key" "flow_logs" {
  #checkov:skip=CKV_AWS_109:Key policies must use Resource "*" (it means "this key")
  #checkov:skip=CKV_AWS_111:Same: key-policy statements apply to this key only
  #checkov:skip=CKV_AWS_356:Same: Resource "*" in a key policy is the key itself
  description             = "Encrypts the VPC flow-log group"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = { ArnLike = { "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${var.account_id}:*" } }
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aegis/${var.name_prefix}/vpc-flow"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.flow_logs.arn
}

resource "aws_iam_role" "flow" {
  name = "${var.name_prefix}-vpc-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow" {
  name = "write-flow-logs"
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
    }]
  })
}

resource "aws_flow_log" "this" {
  vpc_id          = aws_vpc.this.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = aws_iam_role.flow.arn
}