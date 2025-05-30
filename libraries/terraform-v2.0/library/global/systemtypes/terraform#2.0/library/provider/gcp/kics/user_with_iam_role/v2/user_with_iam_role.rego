package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.user_with_iam_role.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

options := {"user:", "allUsers", "allAuthenticatedUsers"}

user_with_iam_role_inner[result] {
	resource := input.document[i].data.google_iam_policy[name]
	tf_lib.check_member(resource.binding, options[_0])
	common_lib.valid_key(resource.binding, "role")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_iam_policy[%s].binding.role is set", [name]), "keyExpectedValue": sprintf("google_iam_policy[%s].binding.role should not be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_iam_policy", "searchKey": sprintf("google_iam_policy[%s].binding.role", [name]), "searchLine": common_lib.build_search_line(["resource", "google_iam_policy", name, "binding", "role"], [])}
}

user_with_iam_role_inner[result] {
	resources := {"google_project_iam_binding", "google_project_iam_member"}
	resource := input.document[i].resource[resources[idx]][name]
	tf_lib.check_member(resource, options[_0])
	common_lib.valid_key(resource, "role")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].role is set", [resources[idx], name]), "keyExpectedValue": sprintf("%s[%s].role should not be set", [resources[idx], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resources[idx], "searchKey": sprintf("%s[%s].role", [resources[idx], name]), "searchLine": common_lib.build_search_line(["resource", resources[idx], name, "role"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: User with IAM Role"
# description: >-
#   As a best practice, it is better to assign an IAM Role to a group than to a user
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.user_with_iam_role"
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
user_with_iam_role_snippet[violation] {
	user_with_iam_role_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
