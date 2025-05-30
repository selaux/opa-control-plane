package global.systemtypes["terraform:2.0"].library.provider.aws.iam.restrict_credential_access.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import future.keywords.in

# METADATA: library-snippet
# version: v1
# title: "AWS: IAM: Restrict Access Key Actions in IAM policies"
# description: "Require AWS/IAM user/group/role policies to not have Create/Update/List/Delete AccessKeys permissions and allow all ('iam:*' or '*') in 'Action'."
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-iam"
# custom:
#   id: "aws.iam.restrict_credential_access"
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
#     - { scope: "resource", service: "iam", name: "user_policy", identifier: "aws_iam_user_policy", argument: "policy" }
#     - { scope: "resource", service: "iam", name: "role_policy", identifier: "aws_iam_role_policy", argument: "policy" }
#     - { scope: "resource", service: "iam", name: "group_policy", identifier: "aws_iam_group_policy", argument: "policy" }
#     - { scope: "resource", service: "iam", name: "policy", identifier: "aws_iam_policy", argument: "policy" }
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
restrict_credential_access_for_iam_policy[violation] {
	prohibit_iam_policy[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

prohibit_iam_policy[violation] {
	resource := util.iam_any_policy_resource_changes[_]
	action := get_action(resource)
	restrict_action(action)

	violation := {
		"message": sprintf("IAM Policy %v has prohibited Actions: %v.", [resource.address, action]),
		"resource": resource,
		"context": {"policy": resource.change.after.policy},
	}
}

get_action(resource) := action {
	policy := json.unmarshal(resource.change.after.policy)
	action := policy.Statement[i].Action
}

restrict_action(actions) {
	some action in actions
	action in denied_actions
}

restrict_action(action) {
	action in denied_actions
}

denied_actions := ["iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:ListAccessKeys", "iam:UpdateAccessKey", "*", "iam:*"]
