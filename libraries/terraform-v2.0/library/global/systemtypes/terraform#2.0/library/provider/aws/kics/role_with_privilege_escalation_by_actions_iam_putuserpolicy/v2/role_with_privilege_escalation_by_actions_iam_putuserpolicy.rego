package global.systemtypes["terraform:2.0"].library.provider.aws.kics.role_with_privilege_escalation_by_actions_iam_putuserpolicy.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

role_with_privilege_escalation_by_actions_iam_putuserpolicy_inner[result] {
	role := input.document[i].resource.aws_iam_role[targetRole]
	common_lib.role_unrecommended_permission_policy_scenarios(targetRole, "iam:PutUserPolicy")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("role %s is associated with a policy that has Action set to 'iam:PutUserPolicy' and Resource set to '*'", [targetRole]), "keyExpectedValue": sprintf("role %s should not be associated with a policy that has Action set to 'iam:PutUserPolicy' and Resource set to '*'", [targetRole]), "resourceName": tf_lib.get_resource_name(role, targetRole), "resourceType": "aws_iam_role", "searchKey": sprintf("aws_iam_role[%s]", [targetRole]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_role", targetRole], [])}
	# get a AWS IAM role

}

# METADATA: library-snippet
# version: v1
# title: "KICS: Role With Privilege Escalation By Actions 'iam:PutUserPolicy'"
# description: >-
#   Role with privilege escalation by actions 'iam:PutUserPolicy' and Resource set to '*'. For more information see https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.role_with_privilege_escalation_by_actions_iam_putuserpolicy"
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
role_with_privilege_escalation_by_actions_iam_putuserpolicy_snippet[violation] {
	role_with_privilege_escalation_by_actions_iam_putuserpolicy_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
