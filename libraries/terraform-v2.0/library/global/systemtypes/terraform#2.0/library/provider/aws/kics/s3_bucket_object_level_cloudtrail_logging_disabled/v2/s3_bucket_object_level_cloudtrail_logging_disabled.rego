package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_object_level_cloudtrail_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

s3_bucket_object_level_cloudtrail_logging_disabled_inner[result] {
	resource := input.document[i].resource.aws_cloudtrail[name]
	resource.event_selector.data_resource.type == "AWS::S3::Object"
	not common_lib.valid_key(resource.event_selector, "read_write_type")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'read_write_type' is undefined or null", "keyExpectedValue": "'read_write_type' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail[%s].event_selector", [name])}
}

s3_bucket_object_level_cloudtrail_logging_disabled_inner[result] {
	resource := input.document[i].resource.aws_cloudtrail[name]
	resource.event_selector.data_resource.type == "AWS::S3::Object"
	resource.event_selector.read_write_type != "All"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'read_write_type' is not set to 'All'", "keyExpectedValue": "'read_write_type' should be set to 'All'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudtrail", "searchKey": sprintf("aws_cloudtrail[%s].event_selector.read_write_type", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket Object Level CloudTrail Logging Disabled"
# description: >-
#   S3 Bucket object-level CloudTrail logging should be enabled for read and write events
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_object_level_cloudtrail_logging_disabled"
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
s3_bucket_object_level_cloudtrail_logging_disabled_snippet[violation] {
	s3_bucket_object_level_cloudtrail_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
