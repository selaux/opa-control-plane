package global.systemtypes["terraform:2.0"].library.provider.aws.network.security_group.whitelisted_ports.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import data.library.parameters

# METADATA: library-snippet
# version: v1
# title: "AWS: Security Groups: Allow only whitelisted Ports for Public Ingress"
# description: Require AWS/Security Groups Ingresses for CIDR "0.0.0.0/0" use only whitelisted ports.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-security_groups"
# custom:
#   id: "aws.network.security_group.whitelisted_ports"
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
#     - { scope: "resource", service: "vpc", name: "security_group_rule", identifier: "aws_security_group_rule", argument: "cidr_blocks" }
#     - { scope: "resource", service: "vpc", name: "security_group_rule", identifier: "aws_security_group_rule", argument: "to_port" }
# schema:
#   parameters:
#     - name: allowed_ports
#       label: "Ports allowed for ingress traffic from cidr '0.0.0.0/0' (e.g., 80 443)"
#       type: set_of_strings
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
security_group_with_whitelisted_ports[violation] {
	insecure_security_group[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), parameters, decision.resource, decision.context),
	}
}

insecure_security_group[obj] {
	count(parameters.allowed_ports) > 0
	resource := util.security_group_resource_changes[_]
	ing := resource.change.after.ingress[_]
	ing.cidr_blocks[_] == "0.0.0.0/0"
	not port_allowed(ing.to_port)

	obj := {
		"message": sprintf("Security Group %v has ingress traffic from 'cidr: 0.0.0.0/0' on an unapproved port %v.", [resource.address, ing.to_port]),
		"resource": resource,
		"context": {"ingress.to_port": ing.to_port},
	}
}

# If parameters are not set then block the ingress traffic for all the ports.
insecure_security_group[obj] {
	count(parameters.allowed_ports) == 0
	resource := util.security_group_resource_changes[_]
	ing := resource.change.after.ingress[_]
	ing.cidr_blocks[_] == "0.0.0.0/0"
	ing.to_port

	obj := {
		"message": sprintf("Security Group %v has ingress traffic from 'cidr: 0.0.0.0/0' on an unapproved port %v.", [resource.address, ing.to_port]),
		"resource": resource,
		"context": {"ingress.to_port": ing.to_port},
	}
}

insecure_security_group[obj] {
	count(parameters.allowed_ports) > 0
	resource := util.security_group_rule_resource_changes[_]
	resource.change.after.type == "ingress"
	resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
	to_port := resource.change.after.to_port
	not port_allowed(to_port)

	obj := {
		"message": sprintf("Security Group %v has ingress traffic from 'cidr: 0.0.0.0/0' on an unapproved port %v.", [resource.address, to_port]),
		"resource": resource,
		"context": {"to_port": to_port},
	}
}

insecure_security_group[obj] {
	count(parameters.allowed_ports) == 0
	resource := util.security_group_rule_resource_changes[_]
	resource.change.after.type == "ingress"
	resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
	ing := resource.change.after.to_port

	obj := {
		"message": sprintf("Security Group %v has ingress traffic from 'cidr: 0.0.0.0/0' on an unapproved port %v.", [resource.address, ing]),
		"resource": resource,
		"context": {"to_port": ing},
	}
}

port_allowed(port) {
	port == to_number(parameters.allowed_ports[_])
}
