package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_without_configured_authorizer.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_without_configured_authorizer_inner[result] {
	restAPI := input.document[i].resource.aws_api_gateway_rest_api[name]
	not has_rest_api_associated(name)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "API Gateway REST API is not associated with an API Gateway Authorizer", "keyExpectedValue": "API Gateway REST API should be associated with an API Gateway Authorizer", "resourceName": tf_lib.get_resource_name(restAPI, name), "resourceType": "aws_api_gateway_rest_api", "searchKey": sprintf("aws_api_gateway_rest_api[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_rest_api", name], [])}
}

has_rest_api_associated(apiName) {
	authorizer := input.document[_].resource.aws_api_gateway_authorizer[name]
	attributeSplit := split(authorizer.rest_api_id, ".")

	attributeSplit[0] == "${aws_api_gateway_rest_api"

	attributeSplit[1] == apiName
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway Without Configured Authorizer"
# description: >-
#   API Gateway REST API should have an API Gateway Authorizer
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_without_configured_authorizer"
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
#       identifier: aws_api_gateway_rest_api
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
api_gateway_without_configured_authorizer_snippet[violation] {
	api_gateway_without_configured_authorizer_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
