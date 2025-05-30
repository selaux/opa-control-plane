package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sagemaker_endpoint_configuration_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sagemaker_endpoint_configuration_encryption_disabled_inner[result] {
	sagemakerEndpoint := input.document[i].resource.aws_sagemaker_endpoint_configuration[name]
	not common_lib.valid_key(sagemakerEndpoint, "kms_key_arn")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_sagemaker_endpoint_configuration[%s] is undefined or null", [name]), "keyExpectedValue": sprintf("aws_sagemaker_endpoint_configuration[%s] should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(sagemakerEndpoint, name), "resourceType": "aws_sagemaker_endpoint_configuration", "searchKey": sprintf("aws_sagemaker_endpoint_configuration[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Sagemaker Endpoint Configuration Encryption Disabled"
# description: >-
#   Sagemaker endpoint configuration should encrypt data
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sagemaker_endpoint_configuration_encryption_disabled"
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
#       identifier: aws_sagemaker_endpoint_configuration
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
sagemaker_endpoint_configuration_encryption_disabled_snippet[violation] {
	sagemaker_endpoint_configuration_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
