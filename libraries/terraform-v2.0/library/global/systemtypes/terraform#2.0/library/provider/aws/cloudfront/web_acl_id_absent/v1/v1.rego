package global.systemtypes["terraform:2.0"].library.provider.aws.cloudfront.web_acl_id_absent.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: CloudFront: Prohibit CloudFront distributions without a WAF association"
# description: Requires AWS/CloudFront distributions to be configured with a WAF web ACL ID.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-cloudfront"
# custom:
#   id: "aws.cloudfront.web_acl_id_absent"
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
#     - { scope: "resource", service: "cloudfront", name: "cloudfront_distribution", identifier: "aws_cloudfront_distribution", argument: "web_acl_id" }
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
prohibit_cloudfront_distribution_without_web_acl_id[violation] {
	web_acl_id_absent[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

web_acl_id_absent[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	utils.is_key_defined(cloudfront_distribution.change.after, "web_acl_id")
	cloudfront_distribution.change.after.web_acl_id == null

	obj := {
		"message": sprintf("CloudFront Distribution %v without 'web_acl_id' is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"web_acl_id": cloudfront_distribution.change.after.web_acl_id},
	}
}

web_acl_id_absent[obj] {
	cloudfront_distribution := util.cloudfront_distribution_resource_changes[_]
	not utils.is_key_defined(cloudfront_distribution.change.after, "web_acl_id")

	obj := {
		"message": sprintf("AWS CloudFront Distribution %v with undefined 'web_acl_id' is prohibited.", [cloudfront_distribution.address]),
		"resource": cloudfront_distribution,
		"context": {"web_acl_id": "undefined"},
	}
}
