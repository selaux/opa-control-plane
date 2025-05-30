package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.google_compute_network_using_default_firewall_rule.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

google_compute_network_using_default_firewall_rule_inner[result] {
	computeNetwork := input.document[i].resource.google_compute_network[name]
	firewall := input.document[_].resource.google_compute_firewall[_]
	tf_lib.matches(firewall.network, name)
	contains(firewall.name, "default")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_compute_network[%s]' is using a default firewall rule", [name]), "keyExpectedValue": sprintf("'google_compute_network[%s]' should not be using a default firewall rule", [name]), "resourceName": tf_lib.get_resource_name(computeNetwork, name), "resourceType": "google_compute_network", "searchKey": sprintf("google_compute_network[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "google_compute_network", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Google Compute Network Using Default Firewall Rule"
# description: >-
#   Google Compute Network should not use default firewall rule
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.google_compute_network_using_default_firewall_rule"
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
google_compute_network_using_default_firewall_rule_snippet[violation] {
	google_compute_network_using_default_firewall_rule_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
