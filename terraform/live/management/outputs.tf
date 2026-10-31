output "organization_id" {
  value = module.organization.organization_id
}

output "trail_arn" {
  value = module.trail.trail_arn
}
output "member_account_ids" {
  value = module.organization.member_account_ids
}
