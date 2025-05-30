package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.cluster_master_authentication_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

cluster_master_authentication_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not resource.master_auth
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'master_auth' is undefined", "keyExpectedValue": "Attribute 'master_auth' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary])}
}

cluster_master_authentication_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.master_auth
	not bothDefined(resource.master_auth)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'master_auth.username' is undefined or Attribute 'master_auth.password' is undefined", "keyExpectedValue": "Attribute 'master_auth.username' should be defined and Attribute 'master_auth.password' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].master_auth", [primary])}
}

cluster_master_authentication_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.master_auth
	bothDefined(resource.master_auth)
	not bothFilled(resource.master_auth)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'master_auth.username' is empty or Attribute 'master_auth.password' is empty", "keyExpectedValue": "Attribute 'master_auth.username' should not be empty and Attribute 'master_auth.password' should not be empty", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].master_auth", [primary])}
}

bothDefined(master_auth) {
	master_auth.username
	master_auth.password
}

bothFilled(master_auth) {
	count(master_auth.username) > 0
	count(master_auth.password) > 0
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cluster Master Authentication Disabled"
# description: >-
#   Kubernetes Engine Clusters must have Master Authentication set to enabled, which means the attribute 'master_auth' must have the subattributes 'username' and 'password' defined and not empty
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.cluster_master_authentication_disabled"
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
cluster_master_authentication_disabled_snippet[violation] {
	cluster_master_authentication_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
