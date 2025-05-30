package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.google_project_iam_member_service_account_has_admin_role.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

google_project_iam_member_service_account_has_admin_role_inner[result] {
	projectIam := input.document[i].resource.google_project_iam_member[name]
	startswith(projectIam.member, "serviceAccount:")
	contains(projectIam.role, "roles/iam.serviceAccountAdmin")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_project_iam_member[%s].role is admin", [name]), "keyExpectedValue": sprintf("google_project_iam_member[%s].role should not be admin", [name]), "resourceName": tf_lib.get_resource_name(projectIam, name), "resourceType": "google_project_iam_member", "searchKey": sprintf("google_project_iam_member[%s].role", [name])}
}

google_project_iam_member_service_account_has_admin_role_inner[result] {
	projectIam := input.document[i].resource.google_project_iam_member[name]
	inArray(projectIam.members, "serviceAccount:")
	contains(projectIam.role, "roles/iam.serviceAccountAdmin")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_project_iam_member[%s].role is admin", [name]), "keyExpectedValue": sprintf("google_project_iam_member[%s].role should not be admin", [name]), "resourceName": tf_lib.get_resource_name(projectIam, name), "resourceType": "google_project_iam_member", "searchKey": sprintf("google_project_iam_member[%s].role", [name])}
}

inArray(array, elem) {
	startswith(array[_], elem)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Google Project IAM Member Service Account Has Admin Role"
# description: >-
#   Verifies that Google Project IAM Member Service Account doesn't have an Admin Role associated
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.google_project_iam_member_service_account_has_admin_role"
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
google_project_iam_member_service_account_has_admin_role_snippet[violation] {
	google_project_iam_member_service_account_has_admin_role_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
