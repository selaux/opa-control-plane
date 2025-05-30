package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.iam_audit_not_properly_configured.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

iam_audit_not_properly_configured_inner[result] {
	resource := input.document[i].resource.google_project_iam_audit_config[name]
	resource.service != "allServices"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'service' is '%s'", [resource.service]), "keyExpectedValue": "'service' must be 'allServices'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_project_iam_audit_config", "searchKey": sprintf("google_project_iam_audit_config[%s].service", [name])}
}

iam_audit_not_properly_configured_inner[result] {
	resource := input.document[i].resource.google_project_iam_audit_config[name]
	count(resource.audit_log_config) < 3
	audit_log_config = resource.audit_log_config[j]
	audit_log_config.log_type != "DATA_READ"
	audit_log_config.log_type != "DATA_WRITE"
	audit_log_config.log_type != "ADMIN_READ"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'log_type' is %s", [audit_log_config.log_type]), "keyExpectedValue": "'log_type' must be one of 'DATA_READ', 'DATA_WRITE', or 'ADMIN_READ'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_project_iam_audit_config", "searchKey": sprintf("google_project_iam_audit_config[%s].audit_log_config.log_type", [name])}
}

iam_audit_not_properly_configured_inner[result] {
	resource := input.document[i].resource.google_project_iam_audit_config[name]
	audit_log_config = resource.audit_log_config[_]
	exempted_members = audit_log_config.exempted_members
	count(exempted_members) != 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'exempted_members' is not empty", "keyExpectedValue": "'exempted_members' should be empty", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_project_iam_audit_config", "searchKey": sprintf("google_project_iam_audit_config[%s].audit_log_config.exempted_members", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Audit Not Properly Configured"
# description: >-
#   Audit Logging Configuration is defective
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.iam_audit_not_properly_configured"
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
#       identifier: google_project_iam_audit_config
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
iam_audit_not_properly_configured_snippet[violation] {
	iam_audit_not_properly_configured_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
