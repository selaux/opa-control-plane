package global.systemtypes["terraform:2.0"].library.provider.aws.kics.authentication_without_mfa.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

authentication_without_mfa_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_iam_user_policy[name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_0]
	common_lib.is_allow_effect(statement)
	not_exists_mfa(statement) == "undefined"
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "The attribute(s) 'policy.Statement.Condition' or/and 'policy.Statement.Condition.BoolIfExists' or/and 'policy.Statement.Condition.BoolIfExists.aws:MultiFactorAuthPresent' is/are undefined or null", "keyExpectedValue": "The attributes 'policy.Statement.Condition', 'policy.Statement.Condition.BoolIfExists', and 'policy.Statement.Condition.BoolIfExists.aws:MultiFactorAuthPresent' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_user_policy", "searchKey": sprintf("aws_iam_user_policy[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_user_policy", name, "policy"], [])}
}

authentication_without_mfa_inner[result] {
	doc := input.document[i]
	resource := doc.resource.aws_iam_user_policy[name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_0]
	common_lib.is_allow_effect(statement)
	not_exists_mfa(statement) == "false"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Principal.AWS' doesn't contain ':mfa/' or 'policy.Statement.Condition.BoolIfExists.aws:MultiFactorAuthPresent' is set to false", "keyExpectedValue": "'policy.Statement.Principal.AWS' should contain ':mfa/' or 'policy.Statement.Condition.BoolIfExists.aws:MultiFactorAuthPresent' should be set to true", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_user_policy", "searchKey": sprintf("aws_iam_user_policy[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_user_policy", name, "policy"], [])}
}

not_exists_mfa(statement) = mfa {
	not common_lib.valid_key(statement.Condition.BoolIfExists, "aws:MultiFactorAuthPresent")

	mfa := "undefined"
} else = mfa {
	not common_lib.valid_key(statement.Condition, "BoolIfExists")

	mfa := "undefined"
} else = mfa {
	not common_lib.valid_key(statement, "Condition")

	mfa := "undefined"
} else = mfa {
	statement.Condition.BoolIfExists["aws:MultiFactorAuthPresent"] != "true"
	mfa := "false"
} else = mfa {
	user := statement.Principal.AWS
	not contains(user, ":mfa/")
	mfa := "false"
} else = mfa {
	user := statement.Principal.AWS[_]
	not contains(user, ":mfa/")
	mfa := "false"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Authentication Without MFA"
# description: >-
#   Users should authenticate with MFA (Multi-factor Authentication) to ensure an extra layer of protection when authenticating
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.authentication_without_mfa"
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
authentication_without_mfa_snippet[violation] {
	authentication_without_mfa_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
