package global.systemtypes["terraform:2.0"].library.provider.aws.kics.mq_broker_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

mq_broker_is_publicly_accessible_inner[result] {
	broker := input.document[i].resource.aws_mq_broker[name]
	broker.publicly_accessible == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'publicly_accessible' is set to true", "keyExpectedValue": "'publicly_accessible' should be undefined or set to false", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_specific_resource_name(broker, "aws_mq_broker", name), "resourceType": "aws_mq_broker", "searchKey": sprintf("aws_mq_broker[%s].publicly_accessible", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_mq_broker", name, "publicly_accessible"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: MQ Broker Is Publicly Accessible"
# description: >-
#   Check if any MQ Broker is not publicly accessible
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.mq_broker_is_publicly_accessible"
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
mq_broker_is_publicly_accessible_snippet[violation] {
	mq_broker_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
