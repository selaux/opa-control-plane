package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_role_allows_all_principals_to_assume.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_role_allows_all_principals_to_assume_inner[result] {
	resource := input.document[i].resource.aws_iam_role[name]
	policyResource := resource.assume_role_policy
	policy := common_lib.json_unmarshal(policyResource)
	st := common_lib.get_statement(policy)
	statement := st[_]
	aws := statement.Principal.AWS
	common_lib.is_allow_effect(statement)
	common_lib.allowsAllPrincipalsToAssume(aws, statement)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'assume_role_policy.Statement.Principal.AWS' contains ':root'", "keyExpectedValue": "'assume_role_policy.Statement.Principal.AWS' should not contain ':root'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_role", "searchKey": sprintf("aws_iam_role[%s].assume_role_policy.Principal.AWS", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_role", name, "assume_role_policy", "Principal", "AWS"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Role Allows All Principals To Assume"
# description: >-
#   IAM role allows all services or principals to assume it
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_role_allows_all_principals_to_assume"
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
iam_role_allows_all_principals_to_assume_snippet[violation] {
	iam_role_allows_all_principals_to_assume_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
