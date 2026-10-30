mock_provider "aws" {}

variables {
  subnet_id          = "subnet-00000000"
  security_group_ids = ["sg-00000000"]
  kms_key_arn        = "arn:aws:kms:us-east-1:444444444444:key/00000000-0000-0000-0000-000000000000"
  ami_id             = "ami-00000000"
}

run "no_public_ip" {
  command = plan

  assert {
    condition     = aws_instance.this.associate_public_ip_address == false
    error_message = "Workloads must not get public IPs."
  }
}

run "imdsv2_required" {
  command = plan

  assert {
    condition     = one(aws_instance.this.metadata_options).http_tokens == "required"
    error_message = "IMDSv2 must be required."
  }
}

run "root_volume_encrypted" {
  command = plan

  assert {
    condition     = one(aws_instance.this.root_block_device).encrypted == true
    error_message = "Root volume must be encrypted."
  }
}