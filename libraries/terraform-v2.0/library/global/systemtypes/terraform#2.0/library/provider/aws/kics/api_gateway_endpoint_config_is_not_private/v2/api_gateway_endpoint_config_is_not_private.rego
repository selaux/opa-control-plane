package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_endpoint_config_is_not_private.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_endpoint_config_is_not_private_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_rest_api[name].endpoint_configuration
	resource.types[index] != "PRIVATE"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'aws_api_gateway_rest_api.aws_api_gateway_rest_api.types' is not 'PRIVATE'.", "keyExpectedValue": "'aws_api_gateway_rest_api.aws_api_gateway_rest_api.types' should be 'PRIVATE'.", "remediation": json.marshal({"after": "PRIVATE", "before": sprintf("%s", [resource.types[index]])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_rest_api", "searchKey": sprintf("aws_api_gateway_rest_api[%s].endpoint_configuration.types[%s]", [name, index]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_rest_api", name, "endpoint_configuration", "types", index], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway Endpoint Config is Not Private"
# description: >-
#   The API Endpoint type in API Gateway should be set to PRIVATE so it's not exposed to the public internet
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_endpoint_config_is_not_private"
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
api_gateway_endpoint_config_is_not_private_snippet[violation] {
	api_gateway_endpoint_config_is_not_private_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
