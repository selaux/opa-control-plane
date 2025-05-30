package global.systemtypes["terraform:2.0"].library.provider.aws.kics.amazon_mq_broker_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

amazon_mq_broker_encryption_disabled_inner[result] {
	document := input.document[i]
	resource = document.resource.aws_mq_broker[name]
	not common_lib.valid_key(resource, "encryption_options")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("resource.aws_mq_broker[%s].encryption_options is not defined", [name]), "keyExpectedValue": sprintf("resource.aws_mq_broker[%s].encryption_options should be defined", [name]), "resourceName": tf_lib.get_specific_resource_name(resource, "aws_mq_broker", name), "resourceType": "aws_mq_broker", "searchKey": sprintf("resource.aws_mq_broker[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: AmazonMQ Broker Encryption Disabled"
# description: >-
#   AmazonMQ Broker should have Encryption Options defined
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.amazon_mq_broker_encryption_disabled"
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
#       identifier: aws_mq_broker
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
amazon_mq_broker_encryption_disabled_snippet[violation] {
	amazon_mq_broker_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
