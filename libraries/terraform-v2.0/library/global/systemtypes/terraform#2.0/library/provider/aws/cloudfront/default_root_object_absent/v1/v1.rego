package global.systemtypes["terraform:2.0"].library.provider.aws.cloudfront.default_root_object_absent.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: CloudFront: Prohibit CloudFront distributions without a default root object."
# description: Requires AWS/CloudFront distributions to be configured with a default root object.
# severity: "critical"
# platform: "terraform"
# resource-type: "aws-cloudfront"
# custom:
#   id: "aws.cloudfront.default_root_object_absent"
#   impact: ""
#   remediation: ""
#   severity: "critical"
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
#     - { scope: "resource", service: "cloudfront", name: "cloudfront_distribution", identifier: "aws_cloudfront_distribution", argument: "default_root_object" }
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
prohibit_cloudfront_distribution_without_default_root_object[violation] {
	default_root_object_absent[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

default_root_object_absent[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	utils.is_key_defined(cloudfront_distribution.change.after, "default_root_object")
	cloudfront_distribution.change.after.default_root_object == null

	obj := {
		"message": sprintf("AWS CloudFront Distribution %v without default root object is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"default root object": cloudfront_distribution.change.after.default_root_object},
	}
}

default_root_object_absent[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	not utils.is_key_defined(cloudfront_distribution.change.after, "default_root_object")

	obj := {
		"message": sprintf("AWS CloudFront Distribution %v with undefined default root object is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"default root object": "undefined"},
	}
}
