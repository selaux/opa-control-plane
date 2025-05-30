package global.systemtypes["terraform:2.0"].library.provider.aws.s3.logging_enabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: S3: Ensure Logging is Enabled in S3 Buckets"
# description: "Require AWS/S3 buckets to have logging enabled."
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-s3"
# custom:
#   id: "aws.s3.logging_enabled"
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
#     - { scope: "resource", service: "s3", name: "bucket", identifier: "aws_s3_bucket", argument: "logging" }
#     - { scope: "resource", service: "s3", name: "bucket_logging", identifier: "aws_s3_bucket_logging", argument: "bucket" }
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
logging_enabled[violation] {
	incorrect_logging[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

incorrect_logging[violation] {
	bucket_resource := util.s3_bucket_resource_changes[_]
	not utils.is_key_defined(bucket_resource.change.after, "logging")

	not bucket_logging_resource_present_in_the_module(utils.module_type(bucket_resource))

	violation := {
		"message": sprintf("S3 bucket %v with logging disabled is prohibited.", [bucket_resource.address]),
		"resource": bucket_resource,
		"context": {"logging": null},
	}
}

incorrect_logging[violation] {
	bucket_resource := util.s3_bucket_resource_changes[_]
	not utils.is_key_defined(bucket_resource.change.after, "logging")
	bucket_module := utils.module_type(bucket_resource)
	bucket_logging_resource_present_in_the_module(utils.module_type(bucket_resource))

	bucket_logging_configuration_blocks := util.s3_bucket_logging_conf_resources

	bucket_configuration_address := concat("", ["aws_s3_bucket.", bucket_resource.name])
	not is_reference_to_bucket_present(bucket_configuration_address, bucket_logging_configuration_blocks, bucket_module)

	bucket_name := bucket_resource.change.after.bucket
	not is_reference_to_bucket_present(bucket_name, bucket_logging_configuration_blocks, bucket_module)

	violation := {
		"message": sprintf("S3 bucket %v with logging disabled is prohibited.", [bucket_resource.address]),
		"resource": bucket_resource,
		"context": {"logging": null},
	}
}

bucket_logging_resource_present_in_the_module(bucket_resource_module) {
	bucket_logging_resource := util.s3_bucket_logging_resource_changes[_]
	bucket_logging_resource_module := utils.module_type(bucket_logging_resource)
	bucket_logging_resource_module == bucket_resource_module
}

is_reference_to_bucket_present(bucket_reference, bucket_logging_configuration_blocks, bucket_module) {
	bucket_logging_block := bucket_logging_configuration_blocks[_]
	utils.module_type(bucket_logging_block) == bucket_module
	bucket_reference == bucket_logging_configuration_blocks[_].expressions.bucket.references[_]
}

is_reference_to_bucket_present(bucket_name, bucket_logging_configuration_blocks, bucket_module) {
	bucket_logging_block := bucket_logging_configuration_blocks[_]
	utils.module_type(bucket_logging_block) == bucket_module
	bucket_name == bucket_logging_configuration_blocks[_].expressions.bucket.constant_value
}
