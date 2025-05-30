package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.service_account_with_improper_privileges.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

service_account_with_improper_privileges_inner[result] {
	resource := input.document[i].data.google_iam_policy[name]
	tf_lib.check_member(resource.binding, "serviceAccount:")
	has_improperly_privileges(resource.binding.role)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_iam_policy[%s].binding.role has admin, editor, owner, or write privilege for service account member", [name]), "keyExpectedValue": sprintf("google_iam_policy[%s].binding.role should not have admin, editor, owner, or write privileges for service account member", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_iam_policy", "searchKey": sprintf("google_iam_policy[%s].binding.role", [name]), "searchLine": common_lib.build_search_line(["resource", "google_iam_policy", name, "binding", "role"], [])}
}

service_account_with_improper_privileges_inner[result] {
	resources := {"google_project_iam_binding", "google_project_iam_member"}
	resource := input.document[i].resource[resources[idx]][name]
	tf_lib.check_member(resource, "serviceAccount:")
	has_improperly_privileges(resource.role)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].role has admin, editor, owner, or write privilege for service account member", [resources[idx], name]), "keyExpectedValue": sprintf("%s[%s].role should not have admin, editor, owner, or write privileges for service account member", [resources[idx], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resources[idx], "searchKey": sprintf("%s[%s].role", [resources[idx], name]), "searchLine": common_lib.build_search_line(["resource", resources[idx], name, "role"], [])}
}

has_improperly_privileges(role) {
	privileges := {"admin", "owner", "editor"}
	contains(lower(role), privileges[x])
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Service Account with Improper Privileges"
# description: >-
#   Service account should not have improper privileges like admin, editor, owner, or write roles
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.service_account_with_improper_privileges"
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
#       identifier: google_iam_policy
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: google_project_iam_binding
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: google_project_iam_member
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
service_account_with_improper_privileges_snippet[violation] {
	service_account_with_improper_privileges_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
