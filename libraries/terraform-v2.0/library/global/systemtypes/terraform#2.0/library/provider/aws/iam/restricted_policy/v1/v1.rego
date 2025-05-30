package global.systemtypes["terraform:2.0"].library.provider.aws.iam.restricted_policy.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: IAM: Prohibit Policies containing an Asterisk"
# description: >-
#   Require AWS/IAM policies not have an asterisk ("*") in Actions nor asterisk ("*") without prefix in Resources.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-iam"
# custom:
#   id: "aws.iam.restricted_policy"
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
#     - { scope: "resource", service: "iam", name: "iam_policy", identifier: "aws_iam_policy", argument: "policy" }
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
restricted_iam_policy[violation] {
	iam_policies[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

iam_policies[obj] {
	actions_in_policy := Actions[_]
	contains(actions_in_policy.actions, "*")

	obj := {
		"message": sprintf("IAM Policy %v has prohibited character '*' (Asterisk) in the Action: %v.", [actions_in_policy.policy.address, actions_in_policy.actions]),
		"resource": actions_in_policy.policy,
		"context": {"policy": actions_in_policy.policy.change.after.policy},
	}
}

iam_policies[obj] {
	resources_in_policy := Resources[_]
	resources_in_policy.resources == "*"

	obj := {
		"message": sprintf("IAM policy %v has prohibited character '*' (Asterisk) in the Resource.", [resources_in_policy.policy.address]),
		"resource": resources_in_policy.policy,
		"context": {"policy": resources_in_policy.policy.change.after.policy},
	}
}

Actions[a] {
	iam_policy := policy_json[_]
	actions := iam_policy.jsons.Statement[_].Action[_]
	a := {"actions": actions, "policy": iam_policy.policy}
}

Actions[a] {
	iam_policy := policy_json[_]
	actions := iam_policy.jsons.Statement[_].Action
	a := {"actions": actions, "policy": iam_policy.policy}
}

Resources[r] {
	iam_policy := policy_json[_]
	resources := iam_policy.jsons.Statement[_].Resource
	r := {"resources": resources, "policy": iam_policy.policy}
}

Resources[r] {
	iam_policy := policy_json[_]
	resources := iam_policy.jsons.Statement[_].Resource[_]
	r := {"resources": resources, "policy": iam_policy.policy}
}

policy_json[p] {
	iam_policy := util.iam_policy_resource_changes[_]
	jsons := json.unmarshal(iam_policy.change.after.policy)
	p := {"policy": iam_policy, "jsons": jsons}
}
