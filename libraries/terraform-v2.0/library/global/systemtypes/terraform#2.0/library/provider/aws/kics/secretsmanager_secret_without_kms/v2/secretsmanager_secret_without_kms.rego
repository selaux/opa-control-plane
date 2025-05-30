package global.systemtypes["terraform:2.0"].library.provider.aws.kics.secretsmanager_secret_without_kms.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

secretsmanager_secret_without_kms_inner[result] {
	resource := input.document[i].resource.aws_secretsmanager_secret[name]
	not common_lib.valid_key(resource, "kms_key_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_secretsmanager_secret.kms_key_id is undefined or null", "keyExpectedValue": "aws_secretsmanager_secret.kms_key_id should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_secretsmanager_secret", "searchKey": sprintf("aws_secretsmanager_secret[{{%s}}]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Secretsmanager Secret Without KMS"
# description: >-
#   AWS Secretmanager should use AWS KMS customer master key (CMK) to encrypt the secret values in the versions stored in the secret
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.secretsmanager_secret_without_kms"
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
#       identifier: aws_secretsmanager_secret
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
secretsmanager_secret_without_kms_snippet[violation] {
	secretsmanager_secret_without_kms_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
