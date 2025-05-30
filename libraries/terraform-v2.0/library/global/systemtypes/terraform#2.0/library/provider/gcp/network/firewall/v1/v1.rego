package global.systemtypes["terraform:2.0"].library.provider.gcp.network.firewall.v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "GCP: Network: Prohibit firewall allowing SSH access over internet"
# description: "Network firewall resource should not allow ingress from '0.0.0.0/0' to port 22."
# severity: "medium"
# platform: "terraform"
# resource-type: "gcp-network"
# custom:
#   id: "gcp.network.firewall"
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
#     name: "google"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - { scope: "resource", service: "compute", name: "firewall", identifier: "google_compute_firewall", argument: "direction" }
#     - { scope: "resource", service: "compute", name: "firewall", identifier: "google_compute_firewall", argument: "source_ranges" }
#     - { scope: "resource", service: "compute", name: "firewall", identifier: "google_compute_firewall", argument: "allow.ports" }
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
prohibit_firewall_with_internet_access[violation] {
	internet_firewall[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

internet_firewall[violation] {
	resource := util.compute_firewall_resource_changes[_]
	after := resource.change.after
	util.is_ingress(after)
	util.is_zero_network(after.source_ranges[_])
	util.port_range_consists_port(after.allow[_].ports[_], 22)

	violation := {
		"message": sprintf("Compute Firewall %v has ingress from '0.0.0.0/0' to prohibited port 22.", [resource.address]),
		"resource": resource,
		"context": {
			"direction": after.direction,
			"source_ranges": after.source_ranges,
			"allow": after.allow,
		},
	}
}
