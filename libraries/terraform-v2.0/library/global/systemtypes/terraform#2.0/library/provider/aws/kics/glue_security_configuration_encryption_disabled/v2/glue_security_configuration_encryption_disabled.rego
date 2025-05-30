package global.systemtypes["terraform:2.0"].library.provider.aws.kics.glue_security_configuration_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

glue_security_configuration_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_glue_security_configuration[name]
	configs := {"cloudwatch_encryption": "cloudwatch_encryption_mode", "job_bookmarks_encryption": "job_bookmarks_encryption_mode", "s3_encryption": "s3_encryption_mode"}
	encryptionConfig := resource.encryption_configuration
	configValue := configs[configKey]
	not common_lib.valid_key(encryptionConfig[configKey], configValue)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_glue_security_configKeyiguration[%s].%s has '%s' undefined or null", [name, configKey, configValue]), "keyExpectedValue": sprintf("aws_glue_security_configuration[%s].%s has '%s' defined and not null", [name, configKey, configValue]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_glue_security_configuration", "searchKey": sprintf("aws_glue_security_configuration[%s].%s", [name, configKey]), "searchLine": common_lib.build_search_line(["resource", "aws_glue_security_configuration", name, configKey], [])}
}

glue_security_configuration_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_glue_security_configuration[name]
	configs := {"cloudwatch_encryption", "job_bookmarks_encryption"}
	config := configs[c]
	not common_lib.valid_key(resource.encryption_configuration[config], "kms_key_arn")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_glue_security_configuration[%s].encryption_configuration.%s has 'kms_key_arn' undefined or null", [name, config]), "keyExpectedValue": sprintf("aws_glue_security_configuration[%s].encryption_configuration.%s has 'kms_key_arn' defined and not null", [name, config]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_glue_security_configuration", "searchKey": sprintf("aws_glue_security_configuration[%s].encryption_configuration.%s", [name, config]), "searchLine": common_lib.build_search_line(["resource", "aws_glue_security_configuration", name, "encryption_configuration", config], [])}
}

glue_security_configuration_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_glue_security_configuration[name]
	searchKeyInfo := wrong_config(resource.encryption_configuration)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": searchKeyInfo.keyActualValue, "keyExpectedValue": searchKeyInfo.keyExpectedValue, "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_glue_security_configuration", "searchKey": sprintf("aws_glue_security_configuration[%s].%s", [name, searchKeyInfo.path]), "searchLine": common_lib.build_search_line(["resource", "aws_glue_security_configuration", name, searchKeyInfo.path], [])}
}

wrong_config(config) = searchKeyInfo {
	config.cloudwatch_encryption.cloudwatch_encryption_mode != "SSE-KMS"
	searchKeyInfo := {
		"path": "encryption_configuration.cloudwatch_encryption.cloudwatch_encryption_mode",
		"keyExpectedValue": "'cloudwatch_encryption_mode' should be set to 'SSE-KMS'",
		"keyActualValue": "'cloudwatch_encryption_mode' is not set to 'SSE-KMS'",
	}
} else = searchKeyInfo {
	config.job_bookmarks_encryption.job_bookmarks_encryption_mode != "CSE-KMS"
	searchKeyInfo := {
		"path": "encryption_configuration.job_bookmarks_encryption.job_bookmarks_encryption_mode",
		"keyExpectedValue": "'job_bookmarks_encryption_mode' should be set to 'CSE-KMS'",
		"keyActualValue": "'job_bookmarks_encryption_mode' is not set to 'CSE-KMS'",
	}
} else = searchKeyInfo {
	config.s3_encryption.s3_encryption_mode == "DISABLED"
	searchKeyInfo := {
		"path": "encryption_configuration.s3_encryption.s3_encryption_mode",
		"keyExpectedValue": "'s3_encryption_mode' should not be set to 'DISABLED'",
		"keyActualValue": "'s3_encryption_mode' is set to 'DISABLED'",
	}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Glue Security Configuration Encryption Disabled"
# description: >-
#   Glue Security Configuration Encryption should have 'cloudwatch_encryption', 'job_bookmarks_encryption' and 's3_encryption' enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.glue_security_configuration_encryption_disabled"
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
#       identifier: aws_glue_security_configuration
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
glue_security_configuration_encryption_disabled_snippet[violation] {
	glue_security_configuration_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
