package global.systemtypes["terraform:2.0"].library.provider.aws.kics.efs_without_kms.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

efs_without_kms_inner[result] {
	efs := input.document[i].resource.aws_efs_file_system[name]
	not efs.kms_key_id
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_efs_file_system[%s].kms_key_id' is undefined", [name]), "keyExpectedValue": sprintf("aws_efs_file_system[%s].kms_key_id' should be defined'", [name]), "resourceName": tf_lib.get_resource_name(efs, name), "resourceType": "aws_efs_file_system", "searchKey": sprintf("aws_efs_file_system[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: EFS Without KMS"
# description: >-
#   Amazon Elastic Filesystem should have filesystem encryption enabled using KMS CMK customer-managed keys instead of AWS managed-keys
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.efs_without_kms"
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
efs_without_kms_snippet[violation] {
	efs_without_kms_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
