output "vpc_id" {
  value = module.network.vpc_id
}

output "data_bucket_name" {
  value = module.data.data_bucket_name
}

output "instance_id" {
  value = module.compute.instance_id
}