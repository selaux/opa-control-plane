package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_policies_with_full_privileges.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_policies_with_full_privileges_inner[result] {
	resourceType := {"aws_iam_group_policy", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}
	resource := input.document[i].resource[resourceType[idx]][name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_0]
	common_lib.is_allow_effect(statement)
	common_lib.equalsOrInArray(statement.Resource, "*")
	common_lib.equalsOrInArray(statement.Action, "*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Action' contains '*'", "keyExpectedValue": "'policy.Statement.Action' shouldn't contain '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType[idx], "searchKey": sprintf("%s[%s].policy", [resourceType[idx], name]), "searchLine": common_lib.build_search_line(["resource", resourceType[idx], name, "policy"], [])}
}

iam_policies_with_full_privileges_inner[result] {
	resource := input.document[i].data.aws_iam_policy_document[name]
	policy := {"Statement": resource.statement}
	st := common_lib.get_statement(policy)
	statement := st[_0]
	common_lib.is_allow_effect(statement)
	common_lib.equalsOrInArray(statement.resources, "*")
	common_lib.equalsOrInArray(statement.actions, "*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Action' contains '*'", "keyExpectedValue": "'policy.Statement.Action' shouldn't contain '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_policy_document", "searchKey": sprintf("aws_iam_policy_document[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_policy_document", name, "policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Policies With Full Privileges"
# description: >-
#   IAM policies shouldn't allow full administrative privileges (for all resources)
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_policies_with_full_privileges"
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
#       identifier: aws_iam_policy_document
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_iam_role_policy
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
iam_policies_with_full_privileges_snippet[violation] {
	iam_policies_with_full_privileges_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
