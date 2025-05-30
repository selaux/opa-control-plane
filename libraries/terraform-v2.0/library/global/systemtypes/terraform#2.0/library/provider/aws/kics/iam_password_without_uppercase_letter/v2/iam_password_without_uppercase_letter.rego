package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_password_without_uppercase_letter.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_password_without_uppercase_letter_inner[result] {
	password_policy := input.document[i].resource.aws_iam_account_password_policy[name]
	not common_lib.valid_key(password_policy, "require_uppercase_characters")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'require_uppercase_characters' is undefined", "keyExpectedValue": "'require_uppercase_characters' should be set with true value", "remediation": "require_uppercase_characters = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(password_policy, name), "resourceType": "aws_iam_account_password_policy", "searchKey": sprintf("aws_iam_account_password_policy[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name], [])}
}

iam_password_without_uppercase_letter_inner[result] {
	password_policy := input.document[i].resource.aws_iam_account_password_policy[name]
	password_policy.require_uppercase_characters == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'require_uppercase_characters' is false", "keyExpectedValue": "'require_uppercase_characters' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(password_policy, name), "resourceType": "aws_iam_account_password_policy", "searchKey": sprintf("aws_iam_account_password_policy[%s].require_uppercase_characters", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name, "require_uppercase_characters"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Password Without Uppercase Letter"
# description: >-
#   IAM password should have at least one uppercase letter
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_password_without_uppercase_letter"
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
#       identifier: aws_iam_account_password_policy
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
iam_password_without_uppercase_letter_snippet[violation] {
	iam_password_without_uppercase_letter_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
