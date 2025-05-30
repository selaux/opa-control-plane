package global.systemtypes["terraform:2.0"].library.provider.aws.kics.user_with_privilege_escalation_by_actions_iam_updateassumerolepolicy_and_sts_assumerole.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

user_with_privilege_escalation_by_actions_iam_updateassumerolepolicy_and_sts_assumerole_inner[result] {
	user := input.document[i].resource.aws_iam_user[targetUser]
	common_lib.user_unrecommended_permission_policy_scenarios(targetUser, "iam:UpdateAssumeRolePolicy")
	common_lib.user_unrecommended_permission_policy_scenarios(targetUser, "sts:AssumeRole")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("user %s is associated with a policy that has Action set to 'iam:UpdateAssumeRolePolicy' and 'sts:AssumeRole' and Resource set to '*'", [targetUser]), "keyExpectedValue": sprintf("user %s shouldn't be associated with a policy that has Action set to 'iam:UpdateAssumeRolePolicy' and 'sts:AssumeRole' and Resource set to '*'", [targetUser]), "resourceName": tf_lib.get_resource_name(user, targetUser), "resourceType": "aws_iam_user", "searchKey": sprintf("aws_iam_user[%s]", [targetUser]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_user", targetUser], [])}
	# get a AWS IAM user

}

# METADATA: library-snippet
# version: v1
# title: "KICS: User With Privilege Escalation By Actions 'iam:UpdateAssumeRolePolicy' And 'sts:AssumeRole'"
# description: >-
#   User with privilege escalation by actions 'iam:UpdateAssumeRolePolicy' and 'sts:AssumeRole' and Resource set to '*'. For more information see https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.user_with_privilege_escalation_by_actions_iam_updateassumerolepolicy_and_sts_assumerole"
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
#       identifier: aws_iam_user
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
user_with_privilege_escalation_by_actions_iam_updateassumerolepolicy_and_sts_assumerole_snippet[violation] {
	user_with_privilege_escalation_by_actions_iam_updateassumerolepolicy_and_sts_assumerole_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
