package main

import rego.v1

pab_flags := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}

# CIS 2.1.5: every public-access-block flag must be true
deny contains msg if {
	some r in input.resource_changes
	r.type == "aws_s3_bucket_public_access_block"
	some flag in pab_flags
	r.change.after[flag] != true
	msg := sprintf("[AEG-S3-001] %s: %s must be true (Block Public Access, CIS 2.1.5)", [r.address, flag])
}

# no public ACLs
deny contains msg if {
	some r in input.resource_changes
	r.type == "aws_s3_bucket_acl"
	r.change.after.acl in {"public-read", "public-read-write", "authenticated-read"}
	msg := sprintf("[AEG-S3-001] %s uses the public ACL %q", [r.address, r.change.after.acl])
}