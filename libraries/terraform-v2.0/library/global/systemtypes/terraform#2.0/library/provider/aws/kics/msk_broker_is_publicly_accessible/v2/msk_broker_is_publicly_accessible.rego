package global.systemtypes["terraform:2.0"].library.provider.aws.kics.msk_broker_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

msk_broker_is_publicly_accessible_inner[result] {
	msk_cluster := input.document[i].resource.aws_msk_cluster[name]
	msk_cluster.broker_node_group_info.connectivity_info.public_access.type == "SERVICE_PROVIDED_EIPS"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_msk_cluster[%s].broker_node_group_info.connectivity_info.public_access.type is set to 'SERVICE_PROVIDED_EIPS'", [name]), "keyExpectedValue": sprintf("aws_msk_cluster[%s].broker_node_group_info.connectivity_info.public_access.type should be set to 'DISABLED' or undefined", [name]), "resourceName": tf_lib.get_specific_resource_name(msk_cluster, "aws_msk_cluster", name), "resourceType": "aws_msk_cluster", "searchKey": sprintf("aws_msk_cluster[%s].broker_node_group_info.connectivity_info.public_access.type", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_msk_cluster", name, "broker_node_group_info", "connectivity_info", "public_access", "type"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: MSK Broker Is Publicly Accessible"
# description: >-
#   Public AWS MSK allows anyone to interact with the Apache Kafka broker, therefore increasing the opportunity for malicious activity. To prevent such a scenario, it is recommended for AWS MSK to not be publicly accessible
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.msk_broker_is_publicly_accessible"
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
#       identifier: aws_msk_cluster
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
msk_broker_is_publicly_accessible_snippet[violation] {
	msk_broker_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
