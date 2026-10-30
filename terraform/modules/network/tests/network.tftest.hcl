mock_provider "aws" {}

variables {
  account_id = "444444444444"
}

run "three_tiers_two_azs" {
  command = plan

  assert {
    condition     = length(aws_subnet.this) == 6
    error_message = "Expected 3 tiers x 2 AZs = 6 subnets."
  }
}

run "no_subnet_hands_out_public_ips" {
  command = plan

  assert {
    condition     = alltrue([for s in aws_subnet.this : s.map_public_ip_on_launch == false])
    error_message = "No subnet may auto-assign public IPs."
  }
}

run "ssh_and_rdp_denied_at_the_edge" {
  command = plan

  assert {
    condition     = aws_network_acl_rule.this["public-in-90"].rule_action == "deny" && aws_network_acl_rule.this["public-in-90"].from_port == 22
    error_message = "Public NACL must explicitly deny SSH (rule 90)."
  }

  assert {
    condition     = aws_network_acl_rule.this["public-in-91"].rule_action == "deny" && aws_network_acl_rule.this["public-in-91"].from_port == 3389
    error_message = "Public NACL must explicitly deny RDP (rule 91)."
  }
}

run "five_interface_endpoints_by_default" {
  command = plan

  assert {
    condition     = length(aws_vpc_endpoint.interface) == 5
    error_message = "Expected ssm, ssmmessages, ec2messages, logs, kms."
  }
}

run "nat_is_opt_in" {
  command = plan

  assert {
    condition     = length(aws_nat_gateway.this) == 0
    error_message = "NAT must be off by default."
  }
}