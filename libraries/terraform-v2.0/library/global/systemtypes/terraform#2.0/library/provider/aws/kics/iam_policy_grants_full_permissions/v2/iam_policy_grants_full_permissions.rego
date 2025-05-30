package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_policy_grants_full_permissions.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_policy_grants_full_permissions_inner[result] {
	resourceType := {"aws_iam_group_policy", "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}
	resource := input.document[i].resource[resourceType[idx]][name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	common_lib.equalsOrInArray(statement.Resource, "*")
	common_lib.equalsOrInArray(statement.Action, "*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Resource' and 'policy.Statement.Action' are equal to '*'", "keyExpectedValue": "'policy.Statement.Resource' and 'policy.Statement.Action' should not equal '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType[idx], "searchKey": sprintf("%s[%s].policy", [resourceType[idx], name]), "searchLine": common_lib.build_search_line(["resource", resourceType[idx], name, "access_policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Policy Grants Full Permissions"
# description: >-
#   IAM policy should not grant full permissions to resources from the get-go, instead of granting permissions gradually as necessary.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_policy_grants_full_permissions"
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
#       identifier: aws_iam_policy
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_iam_user_policy
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
iam_policy_grants_full_permissions_snippet[violation] {
	iam_policy_grants_full_permissions_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
