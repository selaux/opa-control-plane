package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.google_compute_subnetwork_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

google_compute_subnetwork_logging_disabled_inner[result] {
	resource := input.document[i].resource.google_compute_subnetwork[name]
	not common_lib.valid_key(resource, "log_config")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'google_compute_subnetwork[%s].log_config' is undefined or null", [name]), "keyExpectedValue": sprintf("'google_compute_subnetwork[%s].log_config' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_subnetwork", "searchKey": sprintf("google_compute_subnetwork[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Google Compute Subnetwork Logging Disabled"
# description: >-
#   This query checks if logs are enabled for a Google Compute Subnetwork resource.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.google_compute_subnetwork_logging_disabled"
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
google_compute_subnetwork_logging_disabled_snippet[violation] {
	google_compute_subnetwork_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
