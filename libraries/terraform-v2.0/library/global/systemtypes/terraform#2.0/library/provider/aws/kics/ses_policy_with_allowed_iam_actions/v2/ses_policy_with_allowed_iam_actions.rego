package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ses_policy_with_allowed_iam_actions.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ses_policy_with_allowed_iam_actions_inner[result] {
	resource := input.document[i].resource.aws_ses_identity_policy[name]
	tf_lib.allows_action_from_all_principals(resource.policy, "*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy' allows IAM actions to all principals", "keyExpectedValue": "'policy' should not allow IAM actions to all principals", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ses_identity_policy", "searchKey": sprintf("aws_ses_identity_policy[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ses_identity_policy", name, "policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SES Policy With Allowed IAM Actions"
# description: >-
#   SES policy should not allow IAM actions to all principals
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ses_policy_with_allowed_iam_actions"
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
#       identifier: aws_ses_identity_policy
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
ses_policy_with_allowed_iam_actions_snippet[violation] {
	ses_policy_with_allowed_iam_actions_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
