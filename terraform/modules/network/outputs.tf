output "vpc_id" {
  value = aws_vpc.this.id
}

output "private_subnet_ids" {
  value = local.private_subnet_ids
}

output "isolated_subnet_ids" {
  value = [for k, s in aws_subnet.this : s.id if local.subnets[k].tier == "isolated"]
}

output "workload_sg_id" {
  value = aws_security_group.workload.id
}