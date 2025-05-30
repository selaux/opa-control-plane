package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.google_compute_subnetwork_with_private_google_access_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

google_compute_subnetwork_with_private_google_access_disabled_inner[result] {
	resource := input.document[i].resource.google_compute_subnetwork[name]
	not common_lib.valid_key(resource, "private_ip_google_access")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'google_compute_subnetwork[%s].private_ip_google_access' is undefined or null", [name]), "keyExpectedValue": sprintf("'google_compute_subnetwork[%s].private_ip_google_access' should be defined and not null", [name]), "remediation": "private_ip_google_access = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_subnetwork", "searchKey": sprintf("google_compute_subnetwork[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "google_compute_subnetwork", name], [])}
}

google_compute_subnetwork_with_private_google_access_disabled_inner[result] {
	resource := input.document[i].resource.google_compute_subnetwork[name]
	resource.private_ip_google_access == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'google_compute_subnetwork[%s].private_ip_google_access' is set to false", [name]), "keyExpectedValue": sprintf("'google_compute_subnetwork[%s].private_ip_google_access' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_subnetwork", "searchKey": sprintf("google_compute_subnetwork[%s].private_ip_google_access", [name]), "searchLine": common_lib.build_search_line(["resource", "google_compute_subnetwork", name, "private_ip_google_access"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Google Compute Subnetwork with Private Google Access Disabled"
# description: >-
#   Google Compute Subnetwork should have Private Google Access enabled, which means 'private_ip_google_access' should be set to true
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.google_compute_subnetwork_with_private_google_access_disabled"
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
#       identifier: google_compute_subnetwork
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
google_compute_subnetwork_with_private_google_access_disabled_snippet[violation] {
	google_compute_subnetwork_with_private_google_access_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
