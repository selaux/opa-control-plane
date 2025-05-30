package global.systemtypes["terraform:2.0"].library.provider.aws.kics.kinesis_not_encrypted_with_kms.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

kinesis_not_encrypted_with_kms_inner[result] {
	resource := input.document[i].resource.aws_kinesis_stream[name]
	not resource.encryption_type
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_kinesis_stream[%s].encryption_type is undefined", [name]), "keyExpectedValue": sprintf("aws_kinesis_stream[%s].encryption_type should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kinesis_stream", "searchKey": sprintf("aws_kinesis_stream[%s]", [name])}
}

kinesis_not_encrypted_with_kms_inner[result] {
	resource := input.document[i].resource.aws_kinesis_stream[name]
	resource.encryption_type == "NONE"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_kinesis_stream[%s].encryption_type is set but NONE", [name]), "keyExpectedValue": sprintf("aws_kinesis_stream[%s].encryption_type should be set and not NONE", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kinesis_stream", "searchKey": sprintf("aws_kinesis_stream[%s].encryption_type", [name])}
}

kinesis_not_encrypted_with_kms_inner[result] {
	resource := input.document[i].resource.aws_kinesis_stream[name]
	resource.encryption_type == "KMS"
	not resource.kms_key_id
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_kinesis_stream[%s].kms_key_id is undefined", [name]), "keyExpectedValue": sprintf("aws_kinesis_stream[%s].kms_key_id should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kinesis_stream", "searchKey": sprintf("aws_kinesis_stream[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Kinesis Not Encrypted With KMS"
# description: >-
#   AWS Kinesis Streams and metadata should be protected with KMS
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.kinesis_not_encrypted_with_kms"
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
#       identifier: aws_kinesis_stream
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
kinesis_not_encrypted_with_kms_snippet[violation] {
	kinesis_not_encrypted_with_kms_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
