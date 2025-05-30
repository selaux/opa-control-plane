package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.google_container_node_pool_auto_repair_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

google_container_node_pool_auto_repair_disabled_inner[result] {
	nodePool := input.document[i].resource.google_container_node_pool[name]
	nodePool.management.auto_repair == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_container_node_pool[%s].management.auto_repair is false", [name]), "keyExpectedValue": sprintf("google_container_node_pool[%s].management.auto_repair should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(nodePool, name), "resourceType": "google_container_node_pool", "searchKey": sprintf("google_container_node_pool[%s].management.auto_repair", [name]), "searchLine": common_lib.build_search_line(["resource", "google_container_node_pool", name], ["management", "auto_repair"])}
}

google_container_node_pool_auto_repair_disabled_inner[result] {
	nodePool := input.document[i].resource.google_container_node_pool[name]
	not common_lib.valid_key(nodePool, "management")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("google_container_node_pool[%s].management.auto_repair is undefined or null", [name]), "keyExpectedValue": sprintf("google_container_node_pool[%s].management.auto_repair should be defined and not null", [name]), "remediation": "management {\n\t\tauto_repair = true\n\t}\n", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(nodePool, name), "resourceType": "google_container_node_pool", "searchKey": sprintf("google_container_node_pool[%s].management", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Google Container Node Pool Auto Repair Disabled"
# description: >-
#   Google Container Node Pool Auto Repair should be enabled. This service periodically checks for failing nodes and repairs them to ensure a smooth running state.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.google_container_node_pool_auto_repair_disabled"
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
#       identifier: google_container_node_pool
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
google_container_node_pool_auto_repair_disabled_snippet[violation] {
	google_container_node_pool_auto_repair_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
