locals {
  scp_dir   = coalesce(var.scp_dir, "${path.module}/../../../policies/scp")
  scp_files = fileset(local.scp_dir, "*.json")
  scps      = { for f in local.scp_files : trimsuffix(f, ".json") => file("${local.scp_dir}/${f}") }

  attachments = {
    for pair in flatten([
      for ou, names in var.ou_scps : [for n in names : { ou = ou, scp = n }]
    ]) : "${pair.ou}-${pair.scp}" => pair
  }
}

resource "aws_organizations_organization" "this" {
  feature_set                   = "ALL"
  enabled_policy_types          = ["SERVICE_CONTROL_POLICY"]
  aws_service_access_principals = ["cloudtrail.amazonaws.com", "config.amazonaws.com"]
}

resource "aws_organizations_organizational_unit" "this" {
  for_each  = toset(keys(var.ou_scps))
  name      = each.key
  parent_id = aws_organizations_organization.this.roots[0].id
}

resource "aws_organizations_policy" "scp" {
  for_each    = local.scps
  name        = each.key
  description = "AegisCloud SCP: ${each.key}"
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value

  depends_on = [aws_organizations_organization.this]
}
resource "aws_organizations_policy_attachment" "this" {
  for_each  = local.attachments
  policy_id = aws_organizations_policy.scp[each.value.scp].id
  target_id = aws_organizations_organizational_unit.this[each.value.ou].id
}

resource "aws_organizations_account" "member" {
  for_each  = var.create_member_accounts ? var.member_accounts : {}
  name      = each.key
  email     = each.value.email
  parent_id = aws_organizations_organizational_unit.this[each.value.ou].id
  role_name = "OrganizationAccountAccessRole"

  lifecycle {
    ignore_changes = [role_name]
  }
}