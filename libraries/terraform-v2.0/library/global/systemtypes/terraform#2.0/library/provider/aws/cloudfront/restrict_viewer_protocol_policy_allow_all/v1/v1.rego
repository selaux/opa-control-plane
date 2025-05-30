package global.systemtypes["terraform:2.0"].library.provider.aws.cloudfront.restrict_viewer_protocol_policy_allow_all.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: CloudFront: Prohibit CloudFront distributions without an HTTPS viewer protocol policy"
# description: Requires AWS/CloudFront distribution default and ordered cache behaviors to be configured with an 'https-only' or 'redirect-to-https' viewer_protocol_policy.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-cloudfront"
# custom:
#   id: "aws.cloudfront.restrict_viewer_protocol_policy_allow_all"
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
#     - { scope: "resource", service: "cloudfront", name: "cloudfront_distribution", identifier: "aws_cloudfront_distribution", argument: "default_cache_behavior.viewer_protocol_policy" }
#     - { scope: "resource", service: "cloudfront", name: "cloudfront_distribution", identifier: "aws_cloudfront_distribution", argument: "ordered_cache_behavior.viewer_protocol_policy" }
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
prohibit_cloudfront_distribution_without_retricted_viewer_protocol_policy[violation] {
	viewer_protocol_policy_allow_all[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

viewer_protocol_policy_allow_all[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	cloudfront_distribution.change.after.default_cache_behavior[_].viewer_protocol_policy == "allow-all"

	obj := {
		"message": sprintf("AWS CloudFront Distribution %v with 'viewer_protocol_policy' set to 'allow-all' for Default Cache Behavior is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"default_cache_behavior.viewer_protocol_policy": cloudfront_distribution.change.after.default_cache_behavior[_].viewer_protocol_policy},
	}
}

viewer_protocol_policy_allow_all[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	cloudfront_distribution.change.after.ordered_cache_behavior[_].viewer_protocol_policy == "allow-all"

	obj := {
		"message": sprintf("AWS CloudFront Distribution %v with 'viewer_protocol_policy' set to 'allow-all' for Ordered Cache Behavior is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"ordered_cache_behavior.viewer_protocol_policy": cloudfront_distribution.change.after.ordered_cache_behavior[_].viewer_protocol_policy},
	}
}
