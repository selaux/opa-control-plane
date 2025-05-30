package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.network_policy_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

network_policy_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not bothDefined(resource)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'network_policy' is undefined or Attribute 'addons_config' is undefined", "keyExpectedValue": "Attribute 'network_policy' should be defined and Attribute 'addons_config' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary], [])}
}

network_policy_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	bothDefined(resource)
	not resource.addons_config.network_policy_config
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'addons_config.network_policy_config' is undefined", "keyExpectedValue": "Attribute 'addons_config.network_policy_config' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].addons_config", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary], ["addons_config"])}
}

network_policy_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.network_policy.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'network_policy.enabled' is false", "keyExpectedValue": "Attribute 'network_policy.enabled' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].network_policy.enabled", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary], ["network_policy", "enabled"])}
}

network_policy_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.network_policy.enabled == true
	resource.addons_config.network_policy_config.disabled == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'addons_config.network_policy_config.disabled' is true", "keyExpectedValue": "Attribute 'addons_config.network_policy_config.disabled' should be set to false", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].addons_config.network_policy_config.disabled", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary], ["addons_config", "network_policy_config", "disabled"])}
}

bothDefined(resource) {
	resource.network_policy
	resource.addons_config
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Network Policy Disabled"
# description: >-
#   Kubernetes Engine Clusters must have Network Policy enabled, meaning that the attribute 'network_policy.enabled' must be true and the attribute 'addons_config.network_policy_config.disabled' must be false
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.network_policy_disabled"
#   impact: ""
#   remediation: ""
#   severity: "high"
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
#       identifier: google_container_cluster
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
network_policy_disabled_snippet[violation] {
	network_policy_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
