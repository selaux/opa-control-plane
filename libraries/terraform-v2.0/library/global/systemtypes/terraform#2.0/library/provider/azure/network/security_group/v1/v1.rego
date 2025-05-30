package global.systemtypes["terraform:2.0"].library.provider.azure.network.security_group.v1

import data.global.systemtypes["terraform:2.0"].library.provider.azure.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import future.keywords.in

# METADATA: library-snippet
# version: v1
# title: "Azure: Security Groups: Block port 22 for '0.0.0.0/0'"
# description: >-
#   Azure/Network Security Groups should block Inbound traffic on port 22 for "0.0.0.0/0", "Internet", or "*".
# severity: "medium"
# platform: "terraform"
# resource-type: "azure-security_groups"
# custom:
#   id: "azure.network.security_group"
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
#     name: "azurerm"
#     versions:
#       min: "v2"
#       max: "v3"
#   rule_targets:
#     - { scope: "resource", service: "network", name: "network_security_group", identifier: "azurerm_network_security_group", argument: "destination_port_range" }
#     - { scope: "resource", service: "network", name: "network_security_group", identifier: "azurerm_network_security_group", argument: "destination_port_ranges" }
#     - { scope: "resource", service: "network", name: "network_security_rule", identifier: "azurerm_network_security_rule", argument: "destination_port_range" }
#     - { scope: "resource", service: "network", name: "network_security_rule", identifier: "azurerm_network_security_rule", argument: "destination_port_ranges" }
# schema:
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
restrict_network_security_group_for_ssh[violation] {
	insecure_network_security_group[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_network_security_group[violation] {
	resource := util.network_security_group_resource_changes[_]
	security_rule := resource.change.after.security_rule[_]

	security_rule.direction == "Inbound"
	security_rule.access == "Allow"

	is_address_insecure(security_rule)

	destination_port_ranges_not_set(security_rule.destination_port_ranges)
	destination_port_range := security_rule.destination_port_range
	port_range_not_allowed(security_rule.destination_port_range)

	violation := {
		"message": sprintf("Security Group %v allows traffic from 0.0.0.0/0 to prohibited port 22.", [resource.address]),
		"resource": resource,
		"context": {"destination_port_range": security_rule.destination_port_range},
	}
}

insecure_network_security_group[violation] {
	resource := util.network_security_group_resource_changes[_]
	security_rule := resource.change.after.security_rule[_]

	security_rule.direction == "Inbound"
	security_rule.access == "Allow"

	is_address_insecure(security_rule)

	destination_port_range := security_rule.destination_port_ranges[_]
	port_range_not_allowed(destination_port_range)

	violation := {
		"message": sprintf("Security Group %v allows traffic from 0.0.0.0/0 to prohibited port 22.", [resource.address]),
		"resource": resource,
		"context": {"destination_port_ranges": security_rule.destination_port_ranges},
	}
}

insecure_network_security_group[violation] {
	resource := util.network_security_rule_resource_changes[_]
	security_rule := resource.change.after

	security_rule.direction == "Inbound"
	security_rule.access == "Allow"

	is_address_insecure(security_rule)

	destination_port_ranges_not_set(security_rule.destination_port_ranges)
	destination_port_range := security_rule.destination_port_range
	port_range_not_allowed(security_rule.destination_port_range)

	violation := {
		"message": sprintf("Security Rule %v allows traffic from 0.0.0.0/0 to prohibited port 22.", [resource.address]),
		"resource": resource,
		"context": {"destination_port_range": security_rule.destination_port_range},
	}
}

insecure_network_security_group[violation] {
	resource := util.network_security_rule_resource_changes[_]
	security_rule := resource.change.after

	security_rule.direction == "Inbound"
	security_rule.access == "Allow"

	is_address_insecure(security_rule)

	destination_port_range := security_rule.destination_port_ranges[_]
	port_range_not_allowed(destination_port_range)

	violation := {
		"message": sprintf("Security Rule %v allows traffic from 0.0.0.0/0 to prohibited port 22.", [resource.address]),
		"resource": resource,
		"context": {"destination_port_ranges": security_rule.destination_port_ranges},
	}
}

insecure_source_addresses := {"*", "0.0.0.0/0", "Internet"}

is_address_insecure(security_rule) {
	security_rule.source_address_prefix in insecure_source_addresses
}

is_address_insecure(security_rule) {
	security_rule.source_address_prefixes[_] in insecure_source_addresses
}

destination_port_ranges_not_set(ranges) {
	ranges in {[], null}
}

port_range_not_allowed(range) {
	not contains(range, "-")
	to_number(range) == 22
}

port_range_not_allowed(range) {
	contains(range, "-")
	min := to_number(split(range, "-")[0])
	max := to_number(split(range, "-")[1])
	min <= 22
	max >= 22
}

port_range_not_allowed("*")
