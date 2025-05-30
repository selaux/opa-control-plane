package global.systemtypes["terraform:2.0"].library.provider.aws.iam.restrict_iam_user_policy_attachment.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: IAM: Prohibit IAM policies directly being attached to IAM users"
# description: Requires AWS/IAM policies not to be attached directly to IAM users.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-iam"
# custom:
#   id: "aws.iam.restrict_iam_user_policy_attachment"
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
#     - { scope: "resource", service: "iam", name: "iam_user_policy", identifier: "aws_iam_user_policy", argument: "policy" }
#     - { scope: "resource", service: "iam", name: "iam_user_policy_attachment", identifier: "aws_iam_user_policy_attachment", argument: "policy" }
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
restrict_attaching_iam_user_policy[violation] {
	restrict_attaching_iam_user_policy_attachment[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

restrict_attaching_iam_user_policy_attachment[obj] {
	policy_attachment := util.iam_user_policy_resource_changes[_]

	obj := {
		"message": sprintf("Usage of IAM user policy %v is prohibited.", [policy_attachment.address]),
		"resource": policy_attachment,
		"context": {"policy": policy_attachment},
	}
}

restrict_attaching_iam_user_policy_attachment[obj] {
	policy_attachment := util.iam_user_policy_attachment_resource_changes[_]

	obj := {
		"message": sprintf("Usage of IAM user policy attachment %v is prohibited.", [policy_attachment.address]),
		"resource": policy_attachment,
		"context": {"policy": policy_attachment},
	}
}
