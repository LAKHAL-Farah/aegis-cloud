output "boundary_policy_arn" {
  value = aws_iam_policy.boundary.arn
}

output "role_arns" {
  value = {
    break_glass = aws_iam_role.break_glass.arn
    deployer    = aws_iam_role.deployer.arn
    auditor     = aws_iam_role.auditor.arn
  }
}