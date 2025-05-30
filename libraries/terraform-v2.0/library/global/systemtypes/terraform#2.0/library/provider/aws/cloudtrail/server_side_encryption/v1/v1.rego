package global.systemtypes["terraform:2.0"].library.provider.aws.cloudtrail.server_side_encryption.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: CloudTrail: Prohibit CloudTrails without server side encryption"
# description: Require AWS/Cloudtrail to have server side encryption using an AWS KMS key.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-cloudtrail"
# custom:
#   id: "aws.cloudtrail.server_side_encryption"
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
#     - { scope: "resource", service: "cloudtrail", name: "cloudtrail", identifier: "aws_cloudtrail", argument: "kms_key_id" }
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
prohibit_trails_without_server_side_encryption[violation] {
	insecure_cloudtrail[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_cloudtrail[obj] {
	cloudtrail := util.cloudtrail_resource_changes[_]
	not utils.is_key_defined(cloudtrail.change.after, "kms_key_id")

	obj := {
		"message": sprintf("AWS CloudTrail %v does not have 'kms_key_id' defined.", [cloudtrail.address]),
		"resource": cloudtrail,
		"context": {"kms_key_id": "undefined"},
	}
}
