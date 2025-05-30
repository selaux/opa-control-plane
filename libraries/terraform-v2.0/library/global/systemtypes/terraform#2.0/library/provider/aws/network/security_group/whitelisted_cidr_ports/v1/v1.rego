package global.systemtypes["terraform:2.0"].library.provider.aws.network.security_group.whitelisted_cidr_ports.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import data.library.parameters
import future.keywords.in

# METADATA: library-snippet
# version: v1
# title: "AWS: Security Groups: Ingress Allow only whitelisted CIDR and Ports"
# description: "Require AWS/Security Groups to have ingress from whitelisted CIDR blocks on whitelisted ports. To allow all, use wildcard entry '*'."
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-security_groups"
# custom:
#   id: "aws.network.security_group.whitelisted_cidr_ports"
#   impact: ""
#   remediation: ""
#   severity: "medium"
#   resource_category: ""
#   control_category: ""
#   rule_link: "https://docs.styra.com/systems/terraform/snippets"
#   platform:
#     name: "terraform"
#     versions:
#       min: "v0.12"
#       max: "v1.3"
#   provider:
#     name: "aws"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - { scope: "resource", service: "vpc", name: "security_group", identifier: "aws_security_group", argument: "ingress.cidr_blocks" }
#     - { scope: "resource", service: "vpc", name: "security_group", identifier: "aws_security_group", argument: "ingress.to_port" }
#     - { scope: "resource", service: "vpc", name: "security_group_rule", identifier: "aws_security_group_rule", argument: "type" }
#     - { scope: "resource", service: "vpc", name: "security_group_rule", identifier: "aws_security_group_rule", argument: "cidr_blocks" }
#     - { scope: "resource", service: "vpc", name: "security_group_rule", identifier: "aws_security_group_rule", argument: "to_port" }
# schema:
#   parameters:
#     - name: allowed_cidr_ports
#       label: "An object with allowed CIDR ports by address"
#       type: object
#       key:
#         placeholder: "CIDR Block (Example: 10.1.1.0/24)"
#       value:
#         type: set_of_strings
#         placeholder: "Port (Example: 443)"
#       required: true
#   decision:
#     - type: rego
#       key: allowed
#       value: "false"
#     - type: rego
#       key: message
#       value: "violation.message"
#     - type: rego
#       key: metadata
#       value: "violation.metadata"
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[violation]"
security_group_with_whitelisted_cidr_and_ports[violation] {
	insecure_security_group[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), parameters, decision.resource, decision.context),
	}
}

insecure_security_group[violation] {
	resource := util.security_group_resource_changes[_]
	ingress_details := resource.change.after.ingress[_]
	incorrect_cidr_and_port(ingress_details)

	violation := {
		"message": sprintf("Security Group %v has unapproved ingress traffic from CIDR block %v on port %v.", [resource.address, ingress_details.cidr_blocks, ingress_details.to_port]),
		"resource": resource,
		"context": {
			"ingress.cidr_blocks": ingress_details.cidr_blocks,
			"ingress.to_port": ingress_details.to_port,
		},
	}
}

insecure_security_group[violation] {
	resource := util.security_group_rule_resource_changes[_]
	details := resource.change.after
	details.type == "ingress"
	incorrect_cidr_and_port(details)
	groups := security_groups(resource)

	violation := {
		"message": sprintf("Rule %v for Security Groups %v has unapproved ingress traffic from CIDR block %v on port %v.", [resource.address, groups, details.cidr_blocks, details.to_port]),
		"resource": resource,
		"context": {
			"type": "ingress",
			"cidr_blocks": details.cidr_blocks,
			"to_port": details.to_port,
		},
	}
}

security_groups(resource) := groups {
	some module
	config := input.configuration[module].resources[_]
	config.type == "aws_security_group_rule"
	config.address == resource.address

	references := config.expressions.security_group_id.references

	groups := [group.name |
		group := input.configuration[module].resources[_]
		group.type == "aws_security_group"
		group.address in references
	]
} else := []

incorrect_cidr_and_port(ingress) {
	not cidr_allowed(ingress.cidr_blocks)
}

incorrect_cidr_and_port(ingress) {
	cidr_allowed(ingress.cidr_blocks)
	not cidr_wildcard_present
	allowed_cidr_list := get_cidr_list
	net.cidr_contains(allowed_cidr_list[i], ingress.cidr_blocks[_])
	not port_allowed(parameters.allowed_cidr_ports[i], ingress.to_port)
}

incorrect_cidr_and_port(ingress) {
	cidr_allowed(ingress.cidr_blocks)
	cidr_wildcard_present
	allowed_cidr_list := get_cidr_list
	not port_allowed(parameters.allowed_cidr_ports["*"], ingress.to_port)
}

cidr_allowed(cidr_blocks) {
	not cidr_wildcard_present
	allowed_cidr_list := get_cidr_list
	allowed := net.cidr_contains_matches(allowed_cidr_list, cidr_blocks)
	count(allowed) == count(cidr_blocks)
}

cidr_allowed(cidr_blocks) {
	cidr_wildcard_present
}

cidr_wildcard_present {
	allowed_cidr_list := get_cidr_list
	allowed_cidr_list[_] == "*"
}

port_allowed(allowed_port, port) {
	allowed_port[_] != "*"
	to_number(allowed_port[_]) == to_number(port)
}

port_allowed(allowed_port, port) {
	allowed_port[_] == "*"
}

get_cidr_list[list] {
	parameters.allowed_cidr_ports[i]
	list := i
}
