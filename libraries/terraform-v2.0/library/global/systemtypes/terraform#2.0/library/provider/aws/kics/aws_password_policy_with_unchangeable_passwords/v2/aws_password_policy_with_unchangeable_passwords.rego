package global.systemtypes["terraform:2.0"].library.provider.aws.kics.aws_password_policy_with_unchangeable_passwords.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

#allow_users_to_change_password default is true
aws_password_policy_with_unchangeable_passwords_inner[result] {
	pol := input.document[i].resource.aws_iam_account_password_policy[name]
	pol.allow_users_to_change_password == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'allow_users_to_change_password' is equal 'false'", "keyExpectedValue": "'allow_users_to_change_password' should equal 'true'", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(pol, name), "resourceType": "aws_iam_account_password_policy", "searchKey": sprintf("aws_iam_account_password_policy[%s].allow_users_to_change_password", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_account_password_policy", name, "allow_users_to_change_password"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: AWS Password Policy With Unchangeable Passwords"
# description: >-
#   Unchangeable passwords in AWS password policy
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.aws_password_policy_with_unchangeable_passwords"
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
aws_password_policy_with_unchangeable_passwords_snippet[violation] {
	aws_password_policy_with_unchangeable_passwords_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
