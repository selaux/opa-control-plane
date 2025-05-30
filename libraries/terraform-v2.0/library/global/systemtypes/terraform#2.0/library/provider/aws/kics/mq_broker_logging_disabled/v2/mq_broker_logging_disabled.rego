package global.systemtypes["terraform:2.0"].library.provider.aws.kics.mq_broker_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

mq_broker_logging_disabled_inner[result] {
	broker := input.document[i].resource.aws_mq_broker[name]
	logs := broker.logs
	categories := ["general", "audit"]
	some j
	type := categories[j]
	logs[type] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'%s' is set to false", [type]), "keyExpectedValue": "'general' and 'audit' logging should be set to true", "resourceName": tf_lib.get_specific_resource_name(broker, "aws_mq_broker", name), "resourceType": "aws_mq_broker", "searchKey": sprintf("aws_mq_broker[%s].logs.%s", [name, type])}
}

mq_broker_logging_disabled_inner[result] {
	broker := input.document[i].resource.aws_mq_broker[name]
	logs := broker.logs
	categories := ["general", "audit"]
	some j
	type := categories[j]
	not has_key(logs, type)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'general' and/or 'audit' is undefined", "keyExpectedValue": "'general' and 'audit' logging should be set to true", "resourceName": tf_lib.get_specific_resource_name(broker, "aws_mq_broker", name), "resourceType": "aws_mq_broker", "searchKey": sprintf("aws_mq_broker[%s].logs", [name])}
}

mq_broker_logging_disabled_inner[result] {
	broker := input.document[i].resource.aws_mq_broker[name]
	not broker.logs
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'logs' is undefined", "keyExpectedValue": "'logs' should be set and enabling general AND audit logging", "resourceName": tf_lib.get_specific_resource_name(broker, "aws_mq_broker", name), "resourceType": "aws_mq_broker", "searchKey": sprintf("aws_mq_broker[%s]", [name])}
}

has_key(obj, key) {
	_ = obj[key]
}

# METADATA: library-snippet
# version: v1
# title: "KICS: MQ Broker Logging Disabled"
# description: >-
#   Check if MQ Brokers don't have logging enabled in any of the two options possible (audit and general).
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.mq_broker_logging_disabled"
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
mq_broker_logging_disabled_snippet[violation] {
	mq_broker_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
