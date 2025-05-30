package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ecr_repository_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ecr_repository_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_ecr_repository[name]
	not common_lib.valid_key(resource, "encryption_configuration")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'encryption_configuration' is undefined or null", "keyExpectedValue": "'encryption_configuration' should be defined with 'KMS' as encryption type and a KMS key ARN", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecr_repository", "searchKey": sprintf("aws_ecr_repository[%s]", [name])}
}

ecr_repository_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_ecr_repository[name]
	common_lib.valid_key(resource, "encryption_configuration")
	not valid_encryption_configuration(resource)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'encryption_configuration.encryption_type' is not set to 'KMS' and/or 'encryption_configuration.kms_key' does not specify a KMS key ARN", "keyExpectedValue": "'encryption_configuration.encryption_type' should be set to 'KMS' and 'encryption_configuration.kms_key' specifies a KMS key ARN", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecr_repository", "searchKey": sprintf("aws_ecr_repository[%s].encryption_configuration", [name])}
}

valid_encryption_configuration(resource) {
	resource.encryption_configuration.encryption_type == "KMS"
	common_lib.valid_key(resource.encryption_configuration, "kms_key")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ECR Repository Not Encrypted With CMK"
# description: >-
#   ECR repositories should be encrypted with customer-managed keys to meet stricter security and compliance requirements on access control, monitoring, and key rotation
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ecr_repository_not_encrypted"
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
#       identifier: aws_ecr_repository
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
ecr_repository_not_encrypted_snippet[violation] {
	ecr_repository_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
