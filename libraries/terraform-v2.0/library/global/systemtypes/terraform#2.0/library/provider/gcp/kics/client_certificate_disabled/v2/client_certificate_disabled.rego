package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.client_certificate_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

client_certificate_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not resource.master_auth
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'master_auth' is undefined", "keyExpectedValue": "Attribute 'master_auth' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary], [])}
}

client_certificate_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.master_auth
	not resource.master_auth.client_certificate_config
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'client_certificate_config' in 'master_auth' is undefined", "keyExpectedValue": "Attribute 'client_certificate_config' in 'master_auth' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].master_auth", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary, "master_auth"], [])}
}

client_certificate_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.master_auth
	resource.master_auth.client_certificate_config.issue_client_certificate == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'issue_client_certificate' in 'client_certificate_config' is false", "keyExpectedValue": "Attribute 'issue_client_certificate' in 'client_certificate_config' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s].master_auth.client_certificate_config.issue_client_certificate", [primary]), "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", primary, "master_auth", "client_certificate_config", "issue_client_certificate"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Client Certificate Disabled"
# description: >-
#   Kubernetes Clusters must be created with Client Certificate enabled, which means 'master_auth' must have 'client_certificate_config' with the attribute 'issue_client_certificate' equal to true
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.client_certificate_disabled"
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
client_certificate_disabled_snippet[violation] {
	client_certificate_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
