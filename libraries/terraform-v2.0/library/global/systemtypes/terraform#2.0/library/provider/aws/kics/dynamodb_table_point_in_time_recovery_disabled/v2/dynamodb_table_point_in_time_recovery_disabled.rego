package global.systemtypes["terraform:2.0"].library.provider.aws.kics.dynamodb_table_point_in_time_recovery_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

dynamodb_table_point_in_time_recovery_disabled_inner[result] {
	resource := input.document[i].resource[name]
	name == "aws_dynamodb_table"
	res := resource[m]
	res.point_in_time_recovery.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_dynamodb_table.point_in_time_recovery.enabled is set to false", "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.enabled should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_dynamodb_table", "searchKey": sprintf("aws_dynamodb_table[{{%s}}].point_in_time_recovery.enabled", [m]), "searchLine": common_lib.build_search_line(["resource", "aws_dynamodb_table", name, "point_in_time_recovery", "enabled"], [])}
	#"MissingAttribute" / "RedundantAttribute"

}

dynamodb_table_point_in_time_recovery_disabled_inner[result] {
	resource := input.document[i].resource[name]
	name == "aws_dynamodb_table"
	res := resource[m]
	not common_lib.valid_key(res, "point_in_time_recovery")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_dynamodb_table.point_in_time_recovery is missing", "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.enabled should be enabled", "remediation": "point_in_time_recovery {\n\t\t enabled = true \n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_dynamodb_table", "searchKey": sprintf("aws_dynamodb_table[{{%s}}]", [m]), "searchLine": common_lib.build_search_line(["resource", "aws_dynamodb_table", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: DynamoDB Table Point In Time Recovery Disabled"
# description: >-
#   It's considered a best practice to have point in time recovery enabled for DynamoDB Table
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.dynamodb_table_point_in_time_recovery_disabled"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
#       identifier: aws_dynamodb_table
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
dynamodb_table_point_in_time_recovery_disabled_snippet[violation] {
	dynamodb_table_point_in_time_recovery_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
