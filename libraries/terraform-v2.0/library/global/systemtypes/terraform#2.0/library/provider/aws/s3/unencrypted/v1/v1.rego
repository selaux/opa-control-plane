package global.systemtypes["terraform:2.0"].library.provider.aws.s3.unencrypted.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: S3: Prohibit Unencrypted Buckets"
# description: "Require AWS/S3 buckets to be encrypted."
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-s3"
# custom:
#   id: "aws.s3.unencrypted"
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
#     - { scope: "resource", service: "s3", "name": "bucket", identifier: "aws_s3_bucket", argument: "server_side_encryption_configuration.rule.apply_server_side_encryption_by_default" }
#     - { scope: "resource", service: "s3", "name": "bucket_server_side_encryption_configuration", identifier: "aws_s3_bucket_server_side_encryption_configuration", argument: "rule.apply_server_side_encryption_by_default" }
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
unencrypted_s3_bucket[violation] {
	insecure_resources[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

insecure_resources[violation] {
	bucket_resource := util.s3_bucket_resource_changes[_]
	not utils.is_key_defined(bucket_resource.change.after, "server_side_encryption_configuration")

	not bucket_encryption_resource_present_in_the_module(utils.module_type(bucket_resource))

	violation := {
		"message": sprintf("S3 Bucket %v has encryption disabled.", [bucket_resource.address]),
		"resource": bucket_resource,
		"context": {"server_side_encryption_configuration": "undefined"},
	}
}

insecure_resources[violation] {
	bucket_resource := util.s3_bucket_resource_changes[_]
	not utils.is_key_defined(bucket_resource.change.after, "server_side_encryption_configuration")
	bucket_module := utils.module_type(bucket_resource)
	bucket_encryption_resource_present_in_the_module(utils.module_type(bucket_resource))

	bucket_encryption_configuration_blocks := util.s3_bucket_server_side_encryption_configuration_conf_resources

	bucket_configuration_address := concat("", ["aws_s3_bucket.", bucket_resource.name])
	not is_reference_to_bucket_present(bucket_configuration_address, bucket_encryption_configuration_blocks, bucket_module)

	bucket_name := bucket_resource.change.after.bucket
	not is_reference_to_bucket_present(bucket_name, bucket_encryption_configuration_blocks, bucket_module)

	violation := {
		"message": sprintf("S3 Bucket %v has encryption disabled.", [bucket_resource.address]),
		"resource": bucket_resource,
		"context": {"server_side_encryption_configuration": "undefined"},
	}
}

insecure_resources[violation] {
	bucket_encryption_resource := util.s3_bucket_server_side_encryption_configuration_resource_changes[_]
	rule := bucket_encryption_resource.change.after.rule
	not encrypted(rule)

	violation := {
		"message": sprintf("S3 Bucket %v has encryption disabled by %v.", [bucket_encryption_resource.change.after.bucket, bucket_encryption_resource.address]),
		"resource": bucket_encryption_resource,
		"context": {"rule": rule},
	}
}

bucket_encryption_resource_present_in_the_module(bucket_resource_module) {
	bucket_encryption_resource := util.s3_bucket_server_side_encryption_configuration_resource_changes[_]
	bucket_encryption_resource_module := utils.module_type(bucket_encryption_resource)
	bucket_encryption_resource_module == bucket_resource_module
}

is_reference_to_bucket_present(bucket_reference, bucket_encryption_configuration_blocks, bucket_module) {
	bucket_encryption_block := bucket_encryption_configuration_blocks[_]
	utils.module_type(bucket_encryption_block) == bucket_module
	bucket_reference == bucket_encryption_configuration_blocks[_].expressions.bucket.references[_]
}

is_reference_to_bucket_present(bucket_name, bucket_encryption_configuration_blocks, bucket_module) {
	bucket_encryption_block := bucket_encryption_configuration_blocks[_]
	utils.module_type(bucket_encryption_block) == bucket_module
	bucket_name == bucket_encryption_configuration_blocks[_].expressions.bucket.constant_value
}

encrypted(server_side_encryption_configuration) {
	server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default
}

encrypted(rule) {
	rule[_].apply_server_side_encryption_by_default
}
