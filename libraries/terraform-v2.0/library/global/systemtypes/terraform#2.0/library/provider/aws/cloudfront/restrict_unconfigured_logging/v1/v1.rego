package global.systemtypes["terraform:2.0"].library.provider.aws.cloudfront.restrict_unconfigured_logging.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: CloudFront: Prohibit CloudFront distributions without access logging"
# description: Requires AWS/CloudFront distributions to be configured with access logging.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-cloudfront"
# custom:
#   id: "aws.cloudfront.restrict_unconfigured_logging"
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
#     - { scope: "resource", service: "cloudfront", name: "cloudfront_distribution", identifier: "aws_cloudfront_distribution", argument: "logging_config" }
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
prohibit_cloudfront_distribution_without_logging_configuration[violation] {
	logging_not_configured[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

logging_not_configured[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	utils.is_key_defined(cloudfront_distribution.change.after, "logging_config")
	count(cloudfront_distribution.change.after.logging_config) == 0

	obj := {
		"message": sprintf("CloudFront Distribution %v without 'logging_config' is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"logging_config": cloudfront_distribution.change.after.logging_config},
	}
}

logging_not_configured[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	not utils.is_key_defined(cloudfront_distribution.change.after, "logging_config")

	obj := {
		"message": sprintf("CloudFront Distribution %v without 'logging_config' is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"logging_config": "undefined"},
	}
}
