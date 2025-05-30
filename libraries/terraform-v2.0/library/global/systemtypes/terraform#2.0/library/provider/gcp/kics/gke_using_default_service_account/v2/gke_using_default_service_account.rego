package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.gke_using_default_service_account.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

gke_using_default_service_account_inner[result] {
	resource := input.document[i].resource.google_container_cluster[name]
	not common_lib.valid_key(resource.node_config, "service_account")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'service_account' is default", "keyExpectedValue": "'service_account' should not be default", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].node_config", [name]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", name, "node_config"], [])}
}

gke_using_default_service_account_inner[result] {
	resource := input.document[i].resource.google_container_cluster[name]
	contains(resource.node_config.service_account, "default")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'service_account' is default", "keyExpectedValue": "'service_account' should not be default", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].node_config.service_account", [name]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", name, "node_config", "service_account"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: GKE Using Default Service Account"
# description: >-
#   Kubernetes Engine Clusters should not be configured to use the default service account
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.gke_using_default_service_account"
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
gke_using_default_service_account_snippet[violation] {
	gke_using_default_service_account_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
