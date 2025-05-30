package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_access_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_access_logging_disabled_inner[result] {
	api := input.document[i].resource.aws_api_gateway_stage[name]
	not api.access_log_settings
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'access_log_settings' is not defined", "keyExpectedValue": "'access_log_settings' should be defined", "resourceName": tf_lib.get_resource_name(api, name), "resourceType": "aws_api_gateway_stage", "searchKey": sprintf("aws_api_gateway_stage[%s]", [name])}
}

api_gateway_access_logging_disabled_inner[result] {
	api := input.document[i].resource.aws_apigatewayv2_stage[name]
	not api.access_log_settings
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'access_log_settings' is not defined", "keyExpectedValue": "'access_log_settings' should be defined", "resourceName": tf_lib.get_resource_name(api, name), "resourceType": "aws_apigatewayv2_stage", "searchKey": sprintf("aws_apigatewayv2_stage[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway Access Logging Disabled"
# description: >-
#   API Gateway should have Access Log Settings defined
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_access_logging_disabled"
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
#       identifier: aws_api_gateway_stage
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: aws_apigatewayv2_stage
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
api_gateway_access_logging_disabled_snippet[violation] {
	api_gateway_access_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
