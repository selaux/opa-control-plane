package global.systemtypes["terraform:2.0"].library.provider.aws.kics.athena_workgroup_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

athena_workgroup_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_athena_workgroup[name]
	not common_lib.valid_key(resource, "configuration")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_athena_workgroup[{{%s}}].configuration is missing", [name]), "keyExpectedValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration.encryption_configuration should be defined", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_athena_workgroup", "searchKey": sprintf("aws_athena_workgroup[{{%s}}]", [name])}
}

athena_workgroup_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_athena_workgroup[name]
	not common_lib.valid_key(resource.configuration, "result_configuration")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration is missing", [name]), "keyExpectedValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration.encryption_configuration should be defined", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_athena_workgroup", "searchKey": sprintf("aws_athena_workgroup[{{%s}}].configuration", [name])}
}

athena_workgroup_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_athena_workgroup[name]
	not common_lib.valid_key(resource.configuration.result_configuration, "encryption_configuration")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration.encryption_configuration is missing", [name]), "keyExpectedValue": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration.encryption_configuration should be defined", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_athena_workgroup", "searchKey": sprintf("aws_athena_workgroup[{{%s}}].configuration.result_configuration", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Athena Workgroup Not Encrypted"
# description: >-
#   Athena Workgroup query results should be encrypted, for all queries that run in the workgroup
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.athena_workgroup_not_encrypted"
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
#       identifier: aws_athena_workgroup
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
athena_workgroup_not_encrypted_snippet[violation] {
	athena_workgroup_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
