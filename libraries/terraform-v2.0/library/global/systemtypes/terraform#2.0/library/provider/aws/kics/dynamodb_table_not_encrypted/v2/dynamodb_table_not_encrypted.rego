package global.systemtypes["terraform:2.0"].library.provider.aws.kics.dynamodb_table_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

dynamodb_table_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	resource.server_side_encryption.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_dynamodb_table.server_side_encryption.enabled is set to false", "keyExpectedValue": "aws_dynamodb_table.server_side_encryption.enabled should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_dynamodb_table", "searchKey": sprintf("aws_dynamodb_table[{{%s}}].server_side_encryption.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_dynamodb_table", name, "server_side_encryption", "enabled"], [])}
}

dynamodb_table_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	not common_lib.valid_key(resource, "server_side_encryption")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_dynamodb_table.server_side_encryption is missing", "keyExpectedValue": "aws_dynamodb_table.server_side_encryption.enabled should be set to true", "remediation": "server_side_encryption {\n\t\t enabled = true \n\t }", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_dynamodb_table", "searchKey": sprintf("aws_dynamodb_table[{{%s}}]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_dynamodb_table", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: DynamoDB Table Not Encrypted"
# description: >-
#   AWS DynamoDB Tables should have server-side encryption
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.dynamodb_table_not_encrypted"
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
dynamodb_table_not_encrypted_snippet[violation] {
	dynamodb_table_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
