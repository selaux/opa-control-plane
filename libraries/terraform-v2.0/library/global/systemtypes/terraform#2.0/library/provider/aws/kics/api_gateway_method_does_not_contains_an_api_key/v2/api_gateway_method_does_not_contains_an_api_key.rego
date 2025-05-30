package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_method_does_not_contains_an_api_key.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_method_does_not_contains_an_api_key_inner[result] {
	document := input.document[i]
	api = document.resource.aws_api_gateway_method[name]
	not common_lib.valid_key(api, "api_key_required")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("resource.aws_api_gateway_method[%s].api_key_required is undefined", [name]), "keyExpectedValue": sprintf("resource.aws_api_gateway_method[%s].api_key_required should be defined", [name]), "remediation": "api_key_required = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(api, name), "resourceType": "aws_api_gateway_method", "searchKey": sprintf("resource.aws_api_gateway_method[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_method", name], [])}
}

api_gateway_method_does_not_contains_an_api_key_inner[result] {
	document := input.document[i]
	api = document.resource.aws_api_gateway_method[name]
	api.api_key_required != true
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_api_gateway_method[%s].api_key_required is 'false'", [name]), "keyExpectedValue": sprintf("resource.aws_api_gateway_method[%s].api_key_required should be 'true'", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(api, name), "resourceType": "aws_api_gateway_method", "searchKey": sprintf("resource.aws_api_gateway_method[%s].api_key_required", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_method", name, "api_key_required"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway Method Does Not Contains An API Key"
# description: >-
#   An API Key should be required on a method request.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_method_does_not_contains_an_api_key"
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
#       identifier: aws_api_gateway_method
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
api_gateway_method_does_not_contains_an_api_key_snippet[violation] {
	api_gateway_method_does_not_contains_an_api_key_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
