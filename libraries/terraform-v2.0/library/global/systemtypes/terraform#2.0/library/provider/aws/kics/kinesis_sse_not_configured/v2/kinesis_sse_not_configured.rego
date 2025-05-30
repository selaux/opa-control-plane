package global.systemtypes["terraform:2.0"].library.provider.aws.kics.kinesis_sse_not_configured.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

kinesis_sse_not_configured_inner[result] {
	resource := input.document[i].resource.aws_kinesis_firehose_delivery_stream[name]
	resource.kinesis_source_configuration
	not resource.kinesis_source_configuration.kinesis_stream_arn
	resource.server_side_encryption.enabled == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'server_side_encryption' is enabled and attribute 'kinesis_source_configuration' is set", "keyExpectedValue": "Attribute 'server_side_encryption' should be enabled and attribute 'kinesis_source_configuration' should be undefined", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kinesis_firehose_delivery_stream", "searchKey": sprintf("aws_kinesis_firehose_delivery_stream[%s].server_side_encryption.enabled", [name])}
}

kinesis_sse_not_configured_inner[result] {
	resource := input.document[i].resource.aws_kinesis_firehose_delivery_stream[name]
	not resource.server_side_encryption
	not resource.kinesis_source_configuration.kinesis_stream_arn
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'server_side_encryption' is undefined", "keyExpectedValue": "Attribute 'server_side_encryption' should be set", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kinesis_firehose_delivery_stream", "searchKey": sprintf("aws_kinesis_firehose_delivery_stream[%s]", [name])}
}

kinesis_sse_not_configured_inner[result] {
	resource := input.document[i].resource.aws_kinesis_firehose_delivery_stream[name]
	not resource.kinesis_source_configuration
	resource.server_side_encryption
	resource.server_side_encryption.enabled != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'server_side_encryption' is not enabled", "keyExpectedValue": "Attribute 'server_side_encryption' should be enabled", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kinesis_firehose_delivery_stream", "searchKey": sprintf("aws_kinesis_firehose_delivery_stream[%s].server_side_encryption.enabled", [name])}
}

kinesis_sse_not_configured_inner[result] {
	resource := input.document[i].resource.aws_kinesis_firehose_delivery_stream[name]
	not resource.kinesis_source_configuration
	resource.server_side_encryption.enabled == true
	key_type := resource.server_side_encryption.key_type
	not validKeyType(key_type)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'key_type' is invalid", "keyExpectedValue": "Attribute 'key_type' should be valid", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kinesis_firehose_delivery_stream", "searchKey": sprintf("aws_kinesis_firehose_delivery_stream[%s].server_side_encryption.key_type", [name])}
}

kinesis_sse_not_configured_inner[result] {
	resource := input.document[i].resource.aws_kinesis_firehose_delivery_stream[name]
	not resource.kinesis_source_configuration
	resource.server_side_encryption.enabled == true
	key_type := resource.server_side_encryption.key_type
	key_type == "CUSTOMER_MANAGED_CMK"
	not resource.server_side_encryption.key_arn
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'key_type' is CUSTOMER_MANAGED_CMK and attribute 'key_arn' is undefined", "keyExpectedValue": "Attribute 'key_type' should be CUSTOMER_MANAGED_CMK and attribute 'key_arn' should be set", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kinesis_firehose_delivery_stream", "searchKey": sprintf("aws_kinesis_firehose_delivery_stream[%s].server_side_encryption", [name])}
}

validKeyType("AWS_OWNED_CMK") = true

validKeyType("CUSTOMER_MANAGED_CMK") = true

# METADATA: library-snippet
# version: v1
# title: "KICS: Kinesis SSE Not Configured"
# description: >-
#   AWS Kinesis Server data at rest should have Server Side Encryption (SSE) enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.kinesis_sse_not_configured"
#   impact: ""
#   remediation: ""
#   severity: "high"
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
#     - argument: ""
#       identifier: aws_kinesis_firehose_delivery_stream
#       name: ""
#       scope: resource
#       service: ""
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
kinesis_sse_not_configured_snippet[violation] {
	kinesis_sse_not_configured_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
