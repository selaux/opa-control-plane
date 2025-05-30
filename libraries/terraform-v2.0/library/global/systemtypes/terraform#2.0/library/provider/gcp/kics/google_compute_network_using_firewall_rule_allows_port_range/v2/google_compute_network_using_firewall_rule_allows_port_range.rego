package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.google_compute_network_using_firewall_rule_allows_port_range.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

google_compute_network_using_firewall_rule_allows_port_range_inner[result] {
	computeNetwork := input.document[i].resource.google_compute_network[name]
	firewall := input.document[_].resource.google_compute_firewall[_]
	tf_lib.matches(firewall.network, name)
	common_lib.is_ingress(firewall)
	is_port_range(firewall.allow)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_compute_network[%s]' is using a firewall rule that allows access to port range", [name]), "keyExpectedValue": sprintf("'google_compute_network[%s]' should not be using a firewall rule that allows access to port range", [name]), "resourceName": tf_lib.get_resource_name(computeNetwork, name), "resourceType": "google_compute_network", "searchKey": sprintf("google_compute_network[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "google_compute_network", name], [])}
}

is_port_range(allow) {
	is_array(allow)
	regex.match("[0-9]+-[0-9]+", allow[_].ports[_])
	allow[_].ports[_] != "0-65535"
} else {
	is_object(allow)
	regex.match("[0-9]+-[0-9]+", allow.ports[_])
	allow.ports[_] != "0-65535"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Google Compute Network Using Firewall Rule that Allows Port Range"
# description: >-
#   Google Compute Network should not use a firewall rule that allows port range
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.google_compute_network_using_firewall_rule_allows_port_range"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
#     - argument: ""
#       identifier: google_compute_network
#       name: ""
#       scope: resource
#       service: ""
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
google_compute_network_using_firewall_rule_allows_port_range_snippet[violation] {
	google_compute_network_using_firewall_rule_allows_port_range_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
