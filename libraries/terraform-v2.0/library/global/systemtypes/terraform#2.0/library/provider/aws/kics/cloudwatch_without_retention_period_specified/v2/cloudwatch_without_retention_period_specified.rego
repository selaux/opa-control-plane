package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudwatch_without_retention_period_specified.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudwatch_without_retention_period_specified_inner[result] {
	resource := input.document[i].resource.aws_cloudwatch_log_group[name]
	not resource.retention_in_days
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'retention_in_days' is undefined", "keyExpectedValue": "Attribute 'retention_in_days' should be set and valid", "remediation": "retention_in_days = 7", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudwatch_log_group", "searchKey": sprintf("aws_cloudwatch_log_group[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudwatch_log_group", name], [])}
}

cloudwatch_without_retention_period_specified_inner[result] {
	resource := input.document[i].resource.aws_cloudwatch_log_group[name]
	value := resource.retention_in_days
	validValues := [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653]
	count({x | validValues[x]; validValues[x] == value}) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'retention_in_days' is set but invalid", "keyExpectedValue": "Attribute 'retention_in_days' should be set and valid", "remediation": json.marshal({"after": "7", "before": sprintf("%d", [value])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudwatch_log_group", "searchKey": sprintf("aws_cloudwatch_log_group[%s].retention_in_days", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudwatch_log_group", name, "retention_in_days"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudWatch Without Retention Period Specified"
# description: >-
#   AWS CloudWatch Log groups should have retention days specified
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudwatch_without_retention_period_specified"
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
cloudwatch_without_retention_period_specified_snippet[violation] {
	cloudwatch_without_retention_period_specified_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
