package global.systemtypes["terraform:2.0"].library.provider.aws.kics.policy_without_principal.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

policy_without_principal_inner[result] {
	doc := input.document[i].resource
	[path, value] := walk(doc)
	not is_iam_identity_based_policy(path[0])
	policy := common_lib.json_unmarshal(value.policy)
	statement := common_lib.get_statement(policy)[_]
	common_lib.is_allow_effect(statement)
	not has_principal(statement)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'Principal' is undefined", "keyExpectedValue": "'Principal' should be defined", "resourceName": path[1], "resourceType": path[0], "searchKey": sprintf("%s[%s].policy", [path[0], path[1]]), "searchLine": common_lib.build_search_line(["resource", path[0], path[1], "policy"], [])}
}

is_iam_identity_based_policy(resource) {
	iam_identity_based_policy := {"aws_iam_group_policy", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}
	resource == iam_identity_based_policy[_]
}

has_principal(statement) {
	common_lib.valid_key(statement, "Principals") # iam_policy_document
} else {
	common_lib.valid_key(statement, "Principal")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Policy Without Principal"
# description: >-
#   All policies, except IAM identity-based policies, should have the 'Principal' element defined
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.policy_without_principal"
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
#     - argument: ""
#       identifier: aws_kms_key
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
policy_without_principal_snippet[violation] {
	policy_without_principal_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
