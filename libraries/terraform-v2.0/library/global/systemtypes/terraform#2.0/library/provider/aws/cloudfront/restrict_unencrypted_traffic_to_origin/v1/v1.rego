package global.systemtypes["terraform:2.0"].library.provider.aws.cloudfront.restrict_unencrypted_traffic_to_origin.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Requires AWS/CloudFront distributions to be configured with encrypted traffic to origin."
# description: >-
#   Requires AWS/CloudFront distributions to be configured with access logging.
#   Prohibits 'origin_protocol_policy' set to 'http-only' and prohibits 'origin_protocol_policy' set to 'match-viewer' if 'viewer_protocol_policy' is set to 'allow-all'.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-cloudfront"
# custom:
#   id: "aws.cloudfront.restrict_unencrypted_traffic_to_origin"
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
#     - { scope: "resource", service: "cloudfront", name: "cloudfront_distribution", identifier: "aws_cloudfront_distribution", argument: "origin.custom_origin_config.origin_protocol_policy" }
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
prohibit_cloudfront_distribution_without_encrypted_traffic_to_origin[violation] {
	restrict_unencrypted_traffic_to_origin[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

restrict_unencrypted_traffic_to_origin[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	cloudfront_distribution.change.after.origin[_].custom_origin_config[_].origin_protocol_policy == "http-only"

	obj := {
		"message": sprintf("AWS CloudFront Distribution %v with 'origin_protocol_policy' as 'http-only' is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"origin.custom_origin_config.origin_protocol_policy": cloudfront_distribution.change.after.origin[_].custom_origin_config[_].origin_protocol_policy},
	}
}

restrict_unencrypted_traffic_to_origin[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	cloudfront_distribution.change.after.origin[_].custom_origin_config[_].origin_protocol_policy == "match-viewer"
	viewer_protocol_policy_allow_all(cloudfront_distribution)

	obj := {
		"message": sprintf("AWS CloudFront Distribution %v with 'origin_protocol_policy' as 'match-viewer' and 'viewer_protocol_policy' as 'allow-all' is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"origin.custom_origin_config.origin_protocol_policy": cloudfront_distribution.change.after.origin[_].custom_origin_config[_].origin_protocol_policy},
	}
}

viewer_protocol_policy_allow_all(cloudfront_distribution) {
	cloudfront_distribution.change.after.default_cache_behavior[_].viewer_protocol_policy == "allow-all"
}

viewer_protocol_policy_allow_all(cloudfront_distribution) {
	cloudfront_distribution.change.after.ordered_cache_behavior[_].viewer_protocol_policy == "allow-all"
}
