package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_role_policy_passrole_allows_all.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_role_policy_passrole_allows_all_inner[result] {
	resource := input.document[i].resource.aws_iam_role_policy[name]
	policy := resource.policy
	out := common_lib.json_unmarshal(policy)
	st := common_lib.get_statement(out)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	check_passrole(statement)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'aws_iam_role_policy.policy.Statement.Action' iam:passrole has Resource '*'", "keyExpectedValue": "'aws_iam_role_policy.policy.Statement.Action' iam:passrole shouldn't have Resource '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_role_policy", "searchKey": sprintf("aws_iam_role_policy[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_role_policy", name, "policy"], [])}
}

check_passrole(statement) {
	common_lib.equalsOrInArray(statement.Action, "iam:passrole")
	common_lib.equalsOrInArray(statement.Resource, "*")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Role Policy passRole Allows All"
# description: >-
#   Using the iam:passrole action with wildcards (*) in the resource can be overly permissive because it allows iam:passrole permissions on multiple resources
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_role_policy_passrole_allows_all"
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
iam_role_policy_passrole_allows_all_snippet[violation] {
	iam_role_policy_passrole_allows_all_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
