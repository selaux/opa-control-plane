package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.private_cluster_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

private_cluster_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not common_lib.valid_key(resource, "private_cluster_config")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'private_cluster_config' is undefined or null", "keyExpectedValue": "Attribute 'private_cluster_config' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary])}
}

private_cluster_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.private_cluster_config
	not bothDefined(resource.private_cluster_config)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'private_cluster_config.enable_private_endpoint' is undefined or Attribute 'private_cluster_config.enable_private_nodes' is undefined", "keyExpectedValue": "Attribute 'private_cluster_config.enable_private_endpoint' should be defined and Attribute 'private_cluster_config.enable_private_nodes' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].private_cluster_config", [primary])}
}

private_cluster_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	bothDefined(resource.private_cluster_config)
	not bothTrue(resource.private_cluster_config)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'private_cluster_config.enable_private_endpoint' is false or Attribute 'private_cluster_config.enable_private_nodes' is false", "keyExpectedValue": "Attribute 'private_cluster_config.enable_private_endpoint' should be true and Attribute 'private_cluster_config.enable_private_nodes' should be true", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].private_cluster_config", [primary])}
}

bothDefined(private_cluster_config) {
	common_lib.valid_key(private_cluster_config, "enable_private_endpoint")
	common_lib.valid_key(private_cluster_config, "enable_private_nodes")
}

bothTrue(private_cluster_config) {
	private_cluster_config.enable_private_endpoint == true
	private_cluster_config.enable_private_nodes == true
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Private Cluster Disabled"
# description: >-
#   Kubernetes Clusters must be created with Private Clusters enabled, meaning the 'private_cluster_config' must be defined and the attributes 'enable_private_nodes' and 'enable_private_endpoint' must be true
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.private_cluster_disabled"
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
private_cluster_disabled_snippet[violation] {
	private_cluster_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
