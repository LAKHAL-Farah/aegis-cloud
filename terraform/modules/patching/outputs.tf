output "baseline_id" {
  value = aws_ssm_patch_baseline.this.id
}

output "patch_group" {
  value = var.patch_group
}
