package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_user_policy_without_mfa.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_user_policy_without_mfa_inner[result] {
	resource := input.document[i].resource.aws_iam_user_policy[name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	statement.Action == "sts:AssumeRole"
	common_lib.is_allow_effect(statement)
	check_root(statement, resource)
	not check_mfa(statement)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Principal.AWS' doesn't contain ':mfa/' or 'policy.Statement.Condition.BoolIfExists.aws:MultiFactorAuthPresent' is set to false", "keyExpectedValue": "'policy.Statement.Principal.AWS' should contain ':mfa/' or 'policy.Statement.Condition.BoolIfExists.aws:MultiFactorAuthPresent' should be set to true", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_user_policy", "searchKey": sprintf("aws_iam_user_policy[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_user_policy", name, "policy"], [])}
}

check_mfa(statement) {
	statement.Condition.BoolIfExists["aws:MultiFactorAuthPresent"] == "true"
} else {
	user := statement.Principal.AWS
	contains(user, ":mfa/")
} else {
	user := statement.Principal.AWS[_]
	contains(user, ":mfa/")
}

check_root(statement, resource) {
	user := statement.Principal.AWS
	contains(user, "root")
} else {
	user := statement.Principal.AWS[_]
	contains(user, "root")
} else {
	tf_lib.anyPrincipal(statement)
} else {
	options := {"user", "name"}
	contains(resource[options[_]], "root")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM User Policy Without MFA"
# description: >-
#   Check if the root user is authenticated with MFA
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_user_policy_without_mfa"
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
iam_user_policy_without_mfa_snippet[violation] {
	iam_user_policy_without_mfa_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
