package global.systemtypes["terraform:2.0"].library.provider.aws.s3.restrict_asterisk_in_bucket_policy.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: S3: Prohibit Bucket Policies containing An Asterisk In Actions"
# description: Require AWS/S3 bucket policy to not use asterisk in 'Action'.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-s3"
# custom:
#   id: "aws.s3.restrict_asterisk_in_bucket_policy"
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
#     - { scope: "resource", service: "s3", "name": "s3_bucket", identifier: "aws_s3_bucket", argument: "policy" }
#     - { scope: "resource", service: "s3", "name": "s3_bucket_policy", identifier: "aws_s3_bucket_policy", argument: "policy" }
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
restrict_all_actions_in_bucket_policy[violation] {
	prohibit_bucket_policy[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

prohibit_bucket_policy[obj] {
	bucket := util.s3_bucket_resource_changes[_]
	policy := json.unmarshal(bucket.change.after.policy)
	some prohibited
	contains(policy.Statement[prohibited].Action, "*")

	obj := {
		"message": sprintf("S3 Bucket %v contains prohibited action: %v.", [bucket.address, policy.Statement[prohibited].Action]),
		"resource": bucket,
		"context": {"policy.Statement.Action": policy.Statement[prohibited].Action},
	}
}

prohibit_bucket_policy[obj] {
	bucket_policy := util.s3_bucket_policy_resource_changes[_]
	policy := json.unmarshal(bucket_policy.change.after.policy)
	some prohibited
	contains(policy.Statement[prohibited].Action, "*")

	obj := {
		"message": sprintf("S3 Bucket Policy %v contains prohibited action: %v.", [bucket_policy.address, policy.Statement[prohibited].Action]),
		"resource": bucket_policy,
		"context": {"policy.Statement.Action": policy.Statement[prohibited].Action},
	}
}
