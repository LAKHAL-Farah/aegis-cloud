resource "aws_iam_role" "instance" {
  name = "${var.name_prefix}-instance"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.name_prefix}-instance"
  role = aws_iam_role.instance.name
}

resource "aws_instance" "this" {
  #checkov:skip=CKV_AWS_126:Detailed monitoring defaults to true; the LocalStack lab sets it false because MonitorInstances is not implemented (see docs/localstack-limitations.md)
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = var.security_group_ids
  iam_instance_profile        = aws_iam_instance_profile.this.name
  associate_public_ip_address = false
  monitoring                  = var.enable_detailed_monitoring
  ebs_optimized               = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    kms_key_id  = var.kms_key_arn
    volume_type = "gp3"
    volume_size = 8
  }

  tags = { Name = "${var.name_prefix}-app-1" }

  lifecycle {
    # LocalStack reports a public IP even though none was requested, which would
    # force replacement on every plan. Real AWS does not do this; remove on real AWS.
    ignore_changes = [associate_public_ip_address]
  }

}