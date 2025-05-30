package global.systemtypes["terraform:2.0"].library.provider.aws.kics.lambda_function_with_privileged_role.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

privilegeEscalationActions := data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common_json.common_json.common_lib.aws_privilege_escalation_actions

# This query only evaluates the allowance of a set of privileged actions within a given policy context.
# It does not evaluate holistically across all attached policies.
# It considers the only presence of a certain set of actions and its allowance
# in the policy without the context of which resource(s) it applies to.

lambda_function_with_privileged_role_inner[result] {
	document := input.document
	lambda := document[l].resource.aws_lambda_function[function_id]
	document[r].resource.aws_iam_role[role_id]
	split(lambda.role, ".")[1] == role_id
	inline_policy := document[p].resource.aws_iam_role_policy[inline_policy_id]
	split(inline_policy.role, ".")[1] == role_id
	policy := common_lib.json_unmarshal(inline_policy.policy)
	statements := tf_lib.getStatement(policy)
	statement := statements[_0]
	matching_actions := hasPrivilegedPermissions(statement)
	count(matching_actions) > 0
	result := {"documentId": document[l].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_lambda_function[%s].role has been provided privileged permissions through attached inline policy. Provided privileged permissions: '%v'. List of privileged permissions '%v'", [function_id, concat("' , '", matching_actions), privilegeEscalationActions]), "keyExpectedValue": sprintf("aws_lambda_function[%s].role shouldn't have privileged permissions through attached inline policy.", [function_id]), "resourceName": tf_lib.get_resource_name(lambda, function_id), "resourceType": "aws_lambda_function", "searchKey": sprintf("aws_lambda_function[%s].role", [function_id])}
	# For Inline Policy attachment

	# Checking for role whose id matches in the role of lambda arn reference

	# Checking for role's reference in inline policy

}

lambda_function_with_privileged_role_inner[result] {
	document = input.document
	lambda = document[l].resource.aws_lambda_function[function_id]
	role = document[r].resource.aws_iam_role[role_id]
	split(lambda.role, ".")[1] == role_id
	attachments := ["aws_iam_policy_attachment", "aws_iam_role_policy_attachment"]
	attachment := document[_0].resource[attachments[_1]][attachment_id]
	is_attachment(attachment, role_id)
	not regex.match("arn:aws.*:iam::.*", attachment.policy_arn)
	attached_customer_managed_policy_id := split(attachment.policy_arn, ".")[1]
	customer_managed_policy = document[p].resource.aws_iam_policy[attached_customer_managed_policy_id]
	policy := common_lib.json_unmarshal(customer_managed_policy.policy)
	statements := tf_lib.getStatement(policy)
	statement := statements[_2]
	matching_actions := hasPrivilegedPermissions(statement)
	count(matching_actions) > 0
	result := {"documentId": document[l].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_lambda_function[%s].role has been provided privileged permissions through attached managed policy '%v'. Provided privileged permissions: '%v'. List of privileged permissions '%v'", [function_id, attached_customer_managed_policy_id, concat("' , '", matching_actions), privilegeEscalationActions]), "keyExpectedValue": sprintf("aws_lambda_function[%s].role shouldn't have privileged permissions through attached managed policy", [function_id]), "resourceName": tf_lib.get_resource_name(lambda, function_id), "resourceType": "aws_lambda_function", "searchKey": sprintf("aws_lambda_function[%s].role", [function_id])}
	# For Customer Managed Policy Attachment (i.e defined within the current terraform template)

	# Checking for role whose id matches in the role of lambda arn reference

}

lambda_function_with_privileged_role_inner[result] {
	document = input.document
	lambda = document[l].resource.aws_lambda_function[function_id]
	role = document[r].resource.aws_iam_role[role_id]
	split(lambda.role, ".")[1] == role_id
	attachments := ["aws_iam_policy_attachment", "aws_iam_role_policy_attachment"]
	attachment := document[_0].resource[attachments[_1]][attachment_id]
	is_attachment(attachment, role_id)
	regex.match(sprintf("arn:aws.*:iam::policy/%s", [data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common_json.common_json.common_lib.aws_privilege_escalation_policy_names[_2]]), attachment.policy_arn)
	result := {"documentId": document[l].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_lambda_function[%s].role has been provided privileged permissions through attached pre-existing managed policy '%v'.", [function_id, attachment.policy_arn]), "keyExpectedValue": sprintf("aws_lambda_function[%s].role shouldn't have privileged permissions", [function_id]), "resourceName": tf_lib.get_resource_name(lambda, function_id), "resourceType": "aws_lambda_function", "searchKey": sprintf("aws_lambda_function[%s].role", [function_id])}
	# For Pre-existing Managed Policy Attachment (i.e not defined within the current terraform template and hard coded as just policy arn)

	# Checking for role whose id matches in the role of lambda arn reference

	# Looking up of privileged policy_arns

}

is_attachment(attachment, role_id) {
	split(attachment.roles[_], ".")[1] == role_id
} else {
	split(attachment.role, ".")[1] == role_id
}

hasPrivilegedPermissions(statement) = matching_actions {
	statement.Effect == "Allow"
	matching_actions := [matching_actions | action := privilegeEscalationActions[x]; common_lib.check_actions(statement, action); matching_actions := action]
} else = matching_actions {
	matching_actions := []
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Lambda Function With Privileged Role"
# description: >-
#   It is not advisable for AWS Lambda Functions to have privileged permissions.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.lambda_function_with_privileged_role"
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
#       identifier: aws_lambda_function
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
lambda_function_with_privileged_role_snippet[violation] {
	lambda_function_with_privileged_role_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
