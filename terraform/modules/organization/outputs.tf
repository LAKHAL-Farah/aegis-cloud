output "organization_id" {
  value = aws_organizations_organization.this.id
}

output "ou_ids" {
  value = { for k, v in aws_organizations_organizational_unit.this : k => v.id }
}

output "scp_names" {
  value = sort(keys(aws_organizations_policy.scp))
}