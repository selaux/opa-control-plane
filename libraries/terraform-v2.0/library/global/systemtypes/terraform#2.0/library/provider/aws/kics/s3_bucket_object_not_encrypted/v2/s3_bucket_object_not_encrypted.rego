package global.systemtypes["terraform:2.0"].library.provider.aws.kics.s3_bucket_object_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

s3_bucket_object_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_s3_bucket_object[name]
	not common_lib.valid_key(resource, "server_side_encryption")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_s3_bucket_object.server_side_encryption is undefined or null", "keyExpectedValue": "aws_s3_bucket_object.server_side_encryption should be defined and not null", "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket", name), "resourceType": "aws_s3_bucket_object", "searchKey": sprintf("aws_s3_bucket_object[{{%s}}]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: S3 Bucket Object Not Encrypted"
# description: >-
#   S3 Bucket Object should have server-side encryption enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.s3_bucket_object_not_encrypted"
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
#       identifier: aws_s3_bucket_object
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
s3_bucket_object_not_encrypted_snippet[violation] {
	s3_bucket_object_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
