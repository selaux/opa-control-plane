package global.systemtypes["terraform:2.0"].library.provider.aws.kics.msk_cluster_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

msk_cluster_logging_disabled_inner[result] {
	msk_cluster := input.document[i].resource.aws_msk_cluster[name]
	tech := msk_cluster.logging_info.broker_logs[instanceType]
	not tech.enabled
	result := {"documentId": input.document[i].id, "issueType": getIssueType(msk_cluster, instanceType), "keyActualValue": sprintf("msk_cluster[%s].logging_info.broker_logs.%s.enabled is %s", [name, instanceType, getActualValue(msk_cluster, instanceType)]), "keyExpectedValue": "'rule.logging_info.broker_logs.enabled' should be 'true' in every entry", "resourceName": tf_lib.get_specific_resource_name(msk_cluster, "aws_msk_cluster", name), "resourceType": "aws_msk_cluster", "searchKey": sprintf(getSearchKey(msk_cluster, instanceType), [name, instanceType])}
}

msk_cluster_logging_disabled_inner[result] {
	msk_cluster := input.document[i].resource.aws_msk_cluster[name]
	msk_cluster.logging_info
	not msk_cluster.logging_info.broker_logs.cloudwatch_logs
	not msk_cluster.logging_info.broker_logs.firehose
	not msk_cluster.logging_info.broker_logs.s3
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'rule.logging_info.broker_logs.cloudwatch_logs', 'rule.logging_info.broker_logs.firehose' and 'rule.logging_info.broker_logs.s3' do not exist", "keyExpectedValue": "Should have at least one of the following keys: 'cloudwatch_logs', 'firehose' or 's3'", "resourceName": tf_lib.get_specific_resource_name(msk_cluster, "aws_msk_cluster", name), "resourceType": "aws_msk_cluster", "searchKey": sprintf("msk_cluster[%s].logging_info.broker_logs", [name])}
}

msk_cluster_logging_disabled_inner[result] {
	msk_cluster := input.document[i].resource.aws_msk_cluster[name]
	not msk_cluster.logging_info
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'rule.logging_info' does not exist", "keyExpectedValue": "'rule.logging_info' should exist", "resourceName": tf_lib.get_specific_resource_name(msk_cluster, "aws_msk_cluster", name), "resourceType": "aws_msk_cluster", "searchKey": sprintf("aws_msk_cluster[%s]", [name])}
}

getSearchKey(msk_cluster, instanceType) = "aws_msk_cluster[%s].logging_info.broker_logs.%s.enabled" {
	_ = msk_cluster.logging_info.broker_logs[instanceType].enabled
} else = "aws_msk_cluster[%s].logging_info.broker_logs.%s"

getIssueType(msk_cluster, instanceType) = "IncorrectValue" {
	_ = msk_cluster.logging_info.broker_logs[instanceType].enabled
} else = "MissingAttribute"

getActualValue(msk_cluster, instanceType) = "false" {
	_ = msk_cluster.logging_info.broker_logs[instanceType].enabled
} else = "missing"

# METADATA: library-snippet
# version: v1
# title: "KICS: MSK Cluster Logging Disabled"
# description: >-
#   Ensure MSK Cluster Logging is enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.msk_cluster_logging_disabled"
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
msk_cluster_logging_disabled_snippet[violation] {
	msk_cluster_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
