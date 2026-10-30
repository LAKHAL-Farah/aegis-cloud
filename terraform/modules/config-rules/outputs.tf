output "rule_names" {
  value = sort(keys(local.rules))
}

output "recorder_name" {
  value = aws_config_configuration_recorder.this.name
}