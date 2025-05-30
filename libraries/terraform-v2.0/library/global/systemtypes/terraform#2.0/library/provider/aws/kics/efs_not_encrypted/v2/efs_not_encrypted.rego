package global.systemtypes["terraform:2.0"].library.provider.aws.kics.efs_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

efs_not_encrypted_inner[result] {
	efs := input.document[i].resource.aws_efs_file_system[name]
	efs.encrypted == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_efs_file_system[%s].encrypted' is false", [name]), "keyExpectedValue": sprintf("aws_efs_file_system[%s].encrypted' should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(efs, name), "resourceType": "aws_efs_file_system", "searchKey": sprintf("aws_efs_file_system[%s].encrypted", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_efs_file_system", name, "encrypted"], [])}
}

efs_not_encrypted_inner[result] {
	efs := input.document[i].resource.aws_efs_file_system[name]
	not common_lib.valid_key(efs, "encrypted")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_efs_file_system[%s].encrypted' is undefined or null", [name]), "keyExpectedValue": sprintf("aws_efs_file_system[%s].encrypted' should be defined and not null", [name]), "remediation": "encrypted = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(efs, name), "resourceType": "aws_efs_file_system", "searchKey": sprintf("aws_efs_file_system[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_efs_file_system", name, "encrypted"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EFS Not Encrypted"
# description: >-
#   Elastic File System (EFS) must be encrypted
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.efs_not_encrypted"
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
#       identifier: aws_efs_file_system
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
efs_not_encrypted_snippet[violation] {
	efs_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
