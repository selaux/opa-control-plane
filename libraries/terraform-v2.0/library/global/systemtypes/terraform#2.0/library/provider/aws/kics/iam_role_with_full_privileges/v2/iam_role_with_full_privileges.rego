package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_role_with_full_privileges.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_role_with_full_privileges_inner[result] {
	resource := input.document[i].resource.aws_iam_role[name]
	policy := common_lib.json_unmarshal(resource.assume_role_policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	common_lib.equalsOrInArray(statement.Resource, "*")
	common_lib.equalsOrInArray(statement.Action, "*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "assume_role_policy.Statement.Action is equal to or contains '*'", "keyExpectedValue": "assume_role_policy.Statement.Action should not equal to, nor contain '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_role", "searchKey": sprintf("aws_iam_role[%s].assume_role_policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_role", name, "assume_role_policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Role With Full Privileges"
# description: >-
#   IAM role policy that allow full administrative privileges (for all resources)
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_role_with_full_privileges"
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
#     name: "aws"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: aws_iam_role
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
iam_role_with_full_privileges_snippet[violation] {
	iam_role_with_full_privileges_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
