package global.systemtypes["terraform:2.0"].library.provider.aws.kics.misconfigured_password_policy_expiration.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

misconfigured_password_policy_expiration_inner[result] {
	expr := input.document[i].resource.aws_iam_account_password_policy[name]
	not expr.max_password_age
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'max_password_age' is missing", "keyExpectedValue": "'max_password_age' should exist", "remediation": "max_password_age = 90", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(expr, name), "resourceType": "aws_iam_account_password_policy", "searchKey": sprintf("aws_iam_account_password_policy[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name], [])}
}

misconfigured_password_policy_expiration_inner[result] {
	expr := input.document[i].resource.aws_iam_account_password_policy[name]
	expr.max_password_age > 90
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'max_password_age' is higher than 90", "keyExpectedValue": "'max_password_age' should be lower than 90", "remediation": json.marshal({"after": "90", "before": sprintf("%d", [expr.max_password_age])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(expr, name), "resourceType": "aws_iam_account_password_policy", "searchKey": sprintf("aws_iam_account_password_policy[%s].max_password_age", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name, "max_password_age"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Misconfigured Password Policy Expiration"
# description: >-
#   No password expiration policy
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.misconfigured_password_policy_expiration"
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
misconfigured_password_policy_expiration_snippet[violation] {
	misconfigured_password_policy_expiration_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
