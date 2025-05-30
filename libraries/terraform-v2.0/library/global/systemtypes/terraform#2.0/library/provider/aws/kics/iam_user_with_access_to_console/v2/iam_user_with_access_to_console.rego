package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_user_with_access_to_console.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_user_with_access_to_console_inner[result] {
	resource := input.document[i].resource.aws_iam_user_login_profile[name]
	user := resource.user
	search := clean_user(user)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s has aws_iam_user_login_profile", [search[0][1]]), "keyExpectedValue": sprintf("%s shouldn't have aws_iam_user_login_profile", [search[0][1]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_user_login_profile", "searchKey": sprintf("%s", [search[0][1]])}
}

clean_user(user) = search {
	search := regex.find_all_string_submatch_n("\\${(.*?)\\}", user, -1)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM User With Access To Console"
# description: >-
#   AWS IAM Users should not have access to console
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_user_with_access_to_console"
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
#     name: "aws"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
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
iam_user_with_access_to_console_snippet[violation] {
	iam_user_with_access_to_console_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
