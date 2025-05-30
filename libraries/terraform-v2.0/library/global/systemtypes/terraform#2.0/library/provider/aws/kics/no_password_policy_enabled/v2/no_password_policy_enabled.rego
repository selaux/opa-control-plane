package global.systemtypes["terraform:2.0"].library.provider.aws.kics.no_password_policy_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

no_password_policy_enabled_inner[result] {
	resource := input.document[i].resource.aws_iam_user_login_profile[name]
	resource.password_reset_required == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'password_reset_required' is false", "keyExpectedValue": "Attribute 'password_reset_required' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_user_login_profile", "searchKey": sprintf("aws_iam_user_login_profile[%s].password_reset_required", [name])}
}

no_password_policy_enabled_inner[result] {
	resource := input.document[i].resource.aws_iam_user_login_profile[name]
	resource.password_length < 14
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'password_length' is smaller than 14", "keyExpectedValue": "Attribute 'password_length' should be 14 or greater", "remediation": json.marshal({"after": "15", "before": sprintf("%d", [resource.password_length])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_user_login_profile", "searchKey": sprintf("aws_iam_user_login_profile[%s].password_length", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: No Password Policy Enabled"
# description: >-
#   IAM password policies should be set through the password minimum length and reset password attributes
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.no_password_policy_enabled"
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
#       identifier: aws_iam_user_login_profile
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
no_password_policy_enabled_snippet[violation] {
	no_password_policy_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
