package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudwatch_log_group_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudwatch_log_group_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_cloudwatch_log_group[name]
	not common_lib.valid_key(resource, "kms_key_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'kms_key_id' is undefined", "keyExpectedValue": "Attribute 'kms_key_id' should be set", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudwatch_log_group", "searchKey": sprintf("aws_cloudwatch_log_group[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudWatch Log Group Without KMS"
# description: >-
#   AWS CloudWatch Log groups should be encrypted using KMS
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudwatch_log_group_not_encrypted"
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
#       identifier: aws_cloudwatch_log_group
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
cloudwatch_log_group_not_encrypted_snippet[violation] {
	cloudwatch_log_group_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
