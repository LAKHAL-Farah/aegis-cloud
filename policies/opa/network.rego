package main

import rego.v1

admin_ports := {22, 3389}

port_range_has_admin(from_port, to_port) if {
	some p in admin_ports
	from_port <= p
	p <= to_port
}

exposes_admin(rule) if rule.ip_protocol == "-1"

exposes_admin(rule) if {
	rule.ip_protocol in {"tcp", "6"}
	port_range_has_admin(rule.from_port, rule.to_port)
}

has_exception(rule) if {
	is_object(rule.tags)
	rule.tags["aegis:exception"] != ""
}

# CIS 5.2: never SSH/RDP (or all ports) from the world. No exceptions allowed.
deny contains msg if {
	some r in input.resource_changes
	r.type == "aws_vpc_security_group_ingress_rule"
	after := r.change.after
	after.cidr_ipv4 == "0.0.0.0/0"
	exposes_admin(after)
	msg := sprintf("[AEG-NET-001] %s opens SSH/RDP or all ports to 0.0.0.0/0 (CIS 5.2)", [r.address])
}

# Any other world-open ingress needs a documented exception: tag aegis:exception = "<why>"
deny contains msg if {
	some r in input.resource_changes
	r.type == "aws_vpc_security_group_ingress_rule"
	after := r.change.after
	after.cidr_ipv4 == "0.0.0.0/0"
	not has_exception(after)
	msg := sprintf("[AEG-NET-003] %s is open to 0.0.0.0/0 without an aegis:exception tag", [r.address])
}

# CIS 5.1: no NACL allow rule from the world to an admin port (the explicit deny rules 90/91 are fine)
deny contains msg if {
	some r in input.resource_changes
	r.type == "aws_network_acl_rule"
	after := r.change.after
	after.egress == false
	after.rule_action == "allow"
	after.cidr_block == "0.0.0.0/0"
	nacl_exposes_admin(after)
	msg := sprintf("[AEG-NET-002] %s allows the world to reach SSH/RDP (CIS 5.1)", [r.address])
}

nacl_exposes_admin(rule) if rule.protocol == "-1"

nacl_exposes_admin(rule) if {
	rule.protocol in {"tcp", "6"}
	port_range_has_admin(rule.from_port, rule.to_port)
}