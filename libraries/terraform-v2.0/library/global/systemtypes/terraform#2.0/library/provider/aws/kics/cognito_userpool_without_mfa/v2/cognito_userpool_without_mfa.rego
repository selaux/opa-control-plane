package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cognito_userpool_without_mfa.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cognito_userpool_without_mfa_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cognito_user_pool[name]
	not common_lib.valid_key(resource, "mfa_configuration")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_cognito_user_pool[%s].mfa_configuration is undefined", [name]), "keyExpectedValue": sprintf("aws_cognito_user_pool[%s].mfa_configuration should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cognito_user_pool", "searchKey": sprintf("aws_cognito_user_pool[%s]", [name])}
}

cognito_userpool_without_mfa_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cognito_user_pool[name]
	not common_lib.inArray(["ON", "OPTIONAL"], resource.mfa_configuration)
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_cognito_user_pool[%s].mfa_configuration is set to '%s'", [name, resource.mfa_configuration]), "keyExpectedValue": sprintf("aws_cognito_user_pool[%s].mfa_configuration should be set to 'ON' or 'OPTIONAL", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cognito_user_pool", "searchKey": sprintf("aws_cognito_user_pool[%s]", [name])}
}

cognito_userpool_without_mfa_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_cognito_user_pool[name]
	common_lib.inArray(["ON", "OPTIONAL"], resource.mfa_configuration)
	not hasRemainingConfiguration(resource)
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_cognito_user_pool[%s] doesn't have 'sms_configuration' or 'software_token_mfa_configuration' defined", [name]), "keyExpectedValue": sprintf("aws_cognito_user_pool[%s] should have 'sms_configuration' or 'software_token_mfa_configuration' defined", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cognito_user_pool", "searchKey": sprintf("aws_cognito_user_pool[%s]", [name])}
}

hasRemainingConfiguration(resource) {
	resource.sms_configuration
}

hasRemainingConfiguration(resource) {
	resource.software_token_mfa_configuration
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cognito UserPool Without MFA"
# description: >-
#   AWS Cognito UserPool should have MFA (Multi-Factor Authentication) defined to users
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cognito_userpool_without_mfa"
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
#       identifier: aws_cognito_user_pool
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
cognito_userpool_without_mfa_snippet[violation] {
	cognito_userpool_without_mfa_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
