package global.systemtypes["terraform:2.0"].library.provider.aws.s3.unencrypted_bucket_object.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: S3: Prohibit Unencrypted Bucket Object"
# description: >-
#   Require AWS/S3 bucket object to be server side encrypted
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-s3"
# custom:
#   id: "aws.s3.unencrypted_bucket_object"
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
#     - { scope: "resource", service: "s3", name: "s3_bucket_object", identifier: "aws_s3_bucket_object", argument: "server_side_encryption" }
#     - { scope: "resource", service: "s3", name: "s3_object", identifier: "aws_s3_object", argument: "server_side_encryption" }
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
unencrypted_s3_bucket_object[violation] {
	insecure_resources[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_resources[violation] {
	object := util.s3_bucket_object_resource_changes[_]
	not utils.is_key_defined(object.change.after, "server_side_encryption")

	violation := {
		"message": sprintf("S3 Bucket Object %v has encryption disabled.", [object.address]),
		"resource": object,
		"context": {"server_side_encryption": "undefined"},
	}
}

insecure_resources[violation] {
	object := util.s3_object_resource_changes[_]
	not utils.is_key_defined(object.change.after, "server_side_encryption")

	violation := {
		"message": sprintf("S3 Object %v has encryption disabled.", [object.address]),
		"resource": object,
		"context": {"server_side_encryption": "undefined"},
	}
}
