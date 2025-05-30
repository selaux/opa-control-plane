package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.gke_legacy_authorization_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

gke_legacy_authorization_enabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.enable_legacy_abac == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'enable_legacy_abac' is true", "keyExpectedValue": "Attribute 'enable_legacy_abac' should be set to false", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].enable_legacy_abac", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary], ["enable_legacy_abac"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: GKE Legacy Authorization Enabled"
# description: >-
#   Kubernetes Engine Clusters must have Legacy Authorization set to disabled, which means the attribute 'enable_legacy_abac' must not be true
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.gke_legacy_authorization_enabled"
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
gke_legacy_authorization_enabled_snippet[violation] {
	gke_legacy_authorization_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
