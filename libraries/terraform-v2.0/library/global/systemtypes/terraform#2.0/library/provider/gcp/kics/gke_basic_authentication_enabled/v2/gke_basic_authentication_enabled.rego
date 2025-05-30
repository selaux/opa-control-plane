package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.gke_basic_authentication_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

gke_basic_authentication_enabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not resource.master_auth
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'master_auth' is undefined", "keyExpectedValue": "Attribute 'master_auth' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary])}
}

gke_basic_authentication_enabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not bothDefined(resource.master_auth)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'username' is undefined or attribute 'master_auth' is undefined", "keyExpectedValue": "Both attribute 'master_auth.username' and 'master_auth.password' should be defined and empty", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].master_auth", [primary])}
}

gke_basic_authentication_enabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	bothDefined(resource.master_auth)
	not bothEmpty(resource.master_auth)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'username' is not empty or attribute 'master_auth' is not empty", "keyExpectedValue": "Both attribute 'master_auth.username' and 'master_auth.password' should be defined and empty", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].master_auth", [primary])}
}

bothDefined(master_auth) {
	master_auth.username
	master_auth.password
}

bothEmpty(master_auth) {
	count(master_auth.username) == 0
	count(master_auth.password) == 0
}

# METADATA: library-snippet
# version: v1
# title: "KICS: GKE Basic Authentication Enabled"
# description: >-
#   GCP - Google Kubernetes Engine (GKE) Basic Authentication must be disabled, which means the username and password provided in the master_auth block must be empty
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.gke_basic_authentication_enabled"
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
gke_basic_authentication_enabled_snippet[violation] {
	gke_basic_authentication_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
