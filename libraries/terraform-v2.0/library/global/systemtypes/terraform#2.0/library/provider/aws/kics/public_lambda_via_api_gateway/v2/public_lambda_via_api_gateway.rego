package global.systemtypes["terraform:2.0"].library.provider.aws.kics.public_lambda_via_api_gateway.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

public_lambda_via_api_gateway_inner[result] {
	resource := input.document[i].resource.aws_lambda_function[name]
	permissionResource := input.document[i].resource.aws_lambda_permission[permissionName]
	contains(permissionResource.function_name, concat(".", ["aws_lambda_function", name]))
	permissionResource.action == "lambda:InvokeFunction"
	principalAllowAPIGateway(permissionResource.principal)
	re_match("/\\*/\\*$", permissionResource.source_arn)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'source_arn' is equal '/*/*'", "keyExpectedValue": "'source_arn' should not equal '/*/*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_lambda_permission", "searchKey": sprintf("aws_lambda_permission[%s].source_arn", [permissionName])}
}

principalAllowAPIGateway(principal) = allow {
	principal == "*"
	allow = true
} else = allow {
	principal == "apigateway.amazonaws.com"
	allow = true
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Public Lambda via API Gateway"
# description: >-
#   Allowing to run lambda function using public API Gateway
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.public_lambda_via_api_gateway"
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
#       identifier: aws_lambda_permission
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
public_lambda_via_api_gateway_snippet[violation] {
	public_lambda_via_api_gateway_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
