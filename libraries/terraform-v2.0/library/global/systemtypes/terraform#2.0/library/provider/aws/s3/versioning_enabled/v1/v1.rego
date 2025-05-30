package global.systemtypes["terraform:2.0"].library.provider.aws.s3.versioning_enabled.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: S3: Ensure Versioning is Enabled for S3 Buckets"
# description: Require AWS/S3 buckets to have versioning enabled.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-s3"
# custom:
#   id: "aws.s3.versioning_enabled"
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
#     - { scope: "resource", service: "s3", "name": "s3_bucket", identifier: "aws_s3_bucket", argument: "versioning.enabled" }
#     - { scope: "resource", service: "s3", "name": "s3_bucket_versioning", identifier: "aws_s3_bucket_versioning", argument: "versioning_configuration.status" }
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
versioning_enabled[violation] {
	s3_resources[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

s3_resources[obj] {
	# Following block will check whether the bucket contains versioning block or not
	# If not, then policy will check if the versioning has been configured using aws_s3_bucket_versioning resource
	bucket_resource := util.s3_bucket_resource_changes[_]
	not utils.is_key_defined(bucket_resource.change.after, "versioning")

	# Following block will check whether the aws_s3_bucket_versioning resource is present in the same module or not
	# If not, then the policy should deny
	not bucket_versioning_resource_present_in_the_module(utils.module_type(bucket_resource))

	obj := {
		"message": sprintf("S3 bucket %v without versioning is prohibited.", [bucket_resource.address]),
		"resource": bucket_resource,
		"context": {"versioning": "undefined"},
	}
}

s3_resources[obj] {
	bucket_resource := util.s3_bucket_resource_changes[_]
	not utils.is_key_defined(bucket_resource.change.after, "versioning")
	bucket_module := utils.module_type(bucket_resource)

	bucket_versioning_configuration_block := util.s3_bucket_versioning_conf_resources
	bucket_configuration_address := concat("", ["aws_s3_bucket.", bucket_resource.name])
	not is_reference_to_bucket_present(bucket_configuration_address, bucket_versioning_configuration_block, bucket_module)

	obj := {
		"message": sprintf("S3 bucket %v without versioning is prohibited.", [bucket_resource.address]),
		"resource": bucket_resource,
		"context": {"versioning": "undefined"},
	}
}

s3_resources[obj] {
	bucket_resource := util.s3_bucket_resource_changes[_]
	versioning_config := bucket_resource.change.after.versioning[_]
	not utils.is_key_defined(versioning_config, "enabled")

	obj := {
		"message": sprintf("S3 bucket %v without versioning enabled is prohibited.", [bucket_resource.address]),
		"resource": bucket_resource,
		"context": {"versioning.enabled": "undefined"},
	}
}

s3_resources[obj] {
	bucket_resource := util.s3_bucket_resource_changes[_]
	bucket_resource.change.after.versioning[_].enabled == false

	obj := {
		"message": sprintf("S3 bucket %v without versioning enabled is prohibited.", [bucket_resource.address]),
		"resource": bucket_resource,
		"context": {"versioning.enabled": false},
	}
}

s3_resources[obj] {
	bucket_versioning_resource := util.s3_bucket_versioning_resource_changes[_]
	versioning_status := bucket_versioning_resource.change.after.versioning_configuration[_].status
	versioning_status != "Enabled"

	obj := {
		"message": sprintf("S3 bucket versioning %v not set to Enabled is prohibited.", [bucket_versioning_resource.address]),
		"resource": bucket_versioning_resource,
		"context": {"versioning_configuration.status": versioning_status},
	}
}

bucket_versioning_resource_present_in_the_module(bucket_resource_module) {
	bucket_versioning_resource := util.s3_bucket_versioning_resource_changes[_]
	bucket_versioning_resource_module := utils.module_type(bucket_versioning_resource)
	bucket_versioning_resource_module == bucket_resource_module
}

is_reference_to_bucket_present(bucket_reference, bucket_versioning_configuration_blocks, bucket_module) {
	bucket_versioning_block := bucket_versioning_configuration_blocks[_]
	utils.module_type(bucket_versioning_block) == bucket_module
	bucket_reference == bucket_versioning_configuration_blocks[_].expressions.bucket.references[_]
}
