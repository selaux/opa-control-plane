package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sns_topic_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sns_topic_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_sns_topic[name]
	not common_lib.valid_key(resource, "kms_master_key_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "SNS Topic is not encrypted", "keyExpectedValue": "SNS Topic should be encrypted", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sns_topic", "searchKey": sprintf("aws_sns_topic[%s]", [name])}
}

sns_topic_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_sns_topic[name]
	resource.kms_master_key_id == ""
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "SNS Topic is not encrypted", "keyExpectedValue": "SNS Topic should be encrypted", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sns_topic", "searchKey": sprintf("aws_sns_topic[%s].kms_master_key_id", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SNS Topic Not Encrypted"
# description: >-
#   SNS (Simple Notification Service) Topic should be encrypted
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sns_topic_not_encrypted"
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
#     - argument: ""
#       identifier: aws_sns_topic
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
sns_topic_not_encrypted_snippet[violation] {
	sns_topic_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
