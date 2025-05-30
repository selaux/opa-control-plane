package global.systemtypes["terraform:2.0"].library.provider.aws.kics.redshift_cluster_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

redshift_cluster_logging_disabled_inner[result] {
	resource := input.document[i].resource.aws_redshift_cluster[name]
	resource.logging.enable == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'aws_redshift_cluster.logging' is false", "keyExpectedValue": "'aws_redshift_cluster.logging' should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_redshift_cluster", "searchKey": sprintf("aws_redshift_cluster[%s].logging.enable", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name, "logging", "enable"], [])}
}

redshift_cluster_logging_disabled_inner[result] {
	resource := input.document[i].resource.aws_redshift_cluster[name]
	not common_lib.valid_key(resource, "logging")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'aws_redshift_cluster.logging' is undefined", "keyExpectedValue": "'aws_redshift_cluster.logging' should be true", "remediation": "logging {\n\t\tenable = true \n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_redshift_cluster", "searchKey": sprintf("aws_redshift_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_redshift_cluster", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redshift Cluster Logging Disabled"
# description: >-
#   Make sure Logging is enabled for Redshift Cluster
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.redshift_cluster_logging_disabled"
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
#       identifier: aws_redshift_cluster
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
redshift_cluster_logging_disabled_snippet[violation] {
	redshift_cluster_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
