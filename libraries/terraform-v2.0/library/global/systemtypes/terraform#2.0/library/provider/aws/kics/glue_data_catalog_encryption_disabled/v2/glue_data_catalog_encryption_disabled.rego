package global.systemtypes["terraform:2.0"].library.provider.aws.kics.glue_data_catalog_encryption_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

glue_data_catalog_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_glue_data_catalog_encryption_settings[name]
	resource.data_catalog_encryption_settings.encryption_at_rest.catalog_encryption_mode != "SSE-KMS"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'catalog_encryption_mode' is not set to 'SSE-KMS'", "keyExpectedValue": "'catalog_encryption_mode' should be set to 'SSE-KMS'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_glue_data_catalog_encryption_settings", "searchKey": sprintf("aws_glue_data_catalog_encryption_settings[%s].data_catalog_encryption_settings.encryption_at_rest.catalog_encryption_mode", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_glue_data_catalog_encryption_settings", name, "data_catalog_encryption_settings", "encryption_at_rest", "catalog_encryption_mode"], [])}
}

glue_data_catalog_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_glue_data_catalog_encryption_settings[name]
	not common_lib.valid_key(resource.data_catalog_encryption_settings.encryption_at_rest, "sse_aws_kms_key_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'sse_aws_kms_key_id' is undefined or null", "keyExpectedValue": "'sse_aws_kms_key_id' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_glue_data_catalog_encryption_settings", "searchKey": sprintf("aws_glue_data_catalog_encryption_settings[%s].data_catalog_encryption_settings.encryption_at_rest", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_glue_data_catalog_encryption_settings", name, "data_catalog_encryption_settings", "encryption_at_rest"], [])}
}

glue_data_catalog_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_glue_data_catalog_encryption_settings[name]
	resource.data_catalog_encryption_settings.connection_password_encryption.return_connection_password_encrypted != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'return_connection_password_encrypted' is not set to true", "keyExpectedValue": "'return_connection_password_encrypted' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_glue_data_catalog_encryption_settings", "searchKey": sprintf("aws_glue_data_catalog_encryption_settings[%s].data_catalog_encryption_settings.connection_password_encryption.return_connection_password_encrypted", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_glue_data_catalog_encryption_settings", name, "data_catalog_encryption_settings", "connection_password_encryption", "return_connection_password_encrypted"], [])}
}

glue_data_catalog_encryption_disabled_inner[result] {
	resource := input.document[i].resource.aws_glue_data_catalog_encryption_settings[name]
	not common_lib.valid_key(resource.data_catalog_encryption_settings.connection_password_encryption, "aws_kms_key_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'aws_kms_key_id' is undefined or null", "keyExpectedValue": "'aws_kms_key_id' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_glue_data_catalog_encryption_settings", "searchKey": sprintf("aws_glue_data_catalog_encryption_settings[%s].data_catalog_encryption_settings.connection_password_encryption", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_glue_data_catalog_encryption_settings", name, "data_catalog_encryption_settings", "connection_password_encryption"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Glue Data Catalog Encryption Disabled"
# description: >-
#   Glue Data Catalog Encryption Settings should have 'connection_password_encryption' and 'encryption_at_rest' enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.glue_data_catalog_encryption_disabled"
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
#       identifier: aws_glue_data_catalog_encryption_settings
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
glue_data_catalog_encryption_disabled_snippet[violation] {
	glue_data_catalog_encryption_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
