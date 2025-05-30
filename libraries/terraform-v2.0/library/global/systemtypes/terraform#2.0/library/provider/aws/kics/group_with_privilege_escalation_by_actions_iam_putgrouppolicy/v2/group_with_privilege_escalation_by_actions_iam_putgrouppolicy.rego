package global.systemtypes["terraform:2.0"].library.provider.aws.kics.group_with_privilege_escalation_by_actions_iam_putgrouppolicy.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

group_with_privilege_escalation_by_actions_iam_putgrouppolicy_inner[result] {
	group := input.document[i].resource.aws_iam_group[targetGroup]
	common_lib.group_unrecommended_permission_policy_scenarios(targetGroup, "iam:PutGroupPolicy")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("group %s is associated with a policy that has Action set to 'iam:PutGroupPolicy' and Resource set to '*'", [targetGroup]), "keyExpectedValue": sprintf("group %s shouldn't be associated with a policy that has Action set to 'iam:PutGroupPolicy' and Resource set to '*'", [targetGroup]), "resourceName": tf_lib.get_resource_name(group, targetGroup), "resourceType": "aws_iam_group", "searchKey": sprintf("aws_iam_group[%s]", [targetGroup]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_group", targetGroup], [])}
	# get a AWS IAM group

}

# METADATA: library-snippet
# version: v1
# title: "KICS: Group With Privilege Escalation By Actions 'iam:PutGroupPolicy'"
# description: >-
#   Group with privilege escalation by actions 'iam:PutGroupPolicy' and Resource set to '*'. For more information see https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.group_with_privilege_escalation_by_actions_iam_putgrouppolicy"
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
group_with_privilege_escalation_by_actions_iam_putgrouppolicy_snippet[violation] {
	group_with_privilege_escalation_by_actions_iam_putgrouppolicy_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
