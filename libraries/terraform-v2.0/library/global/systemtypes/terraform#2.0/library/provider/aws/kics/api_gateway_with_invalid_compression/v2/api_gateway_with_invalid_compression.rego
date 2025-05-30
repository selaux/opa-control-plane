package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_with_invalid_compression.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_with_invalid_compression_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_rest_api[name]
	not resource.minimum_compression_size
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'minimum_compression_size' is undefined", "keyExpectedValue": "Attribute 'minimum_compression_size' should be set and have a value greater than -1 and smaller than 10485760", "remediation": "minimum_compression_size = 0", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_rest_api", "searchKey": sprintf("aws_api_gateway_rest_api[%s]", [name]), "searchLine": commonLib.build_search_line(["resource", "aws_api_gateway_rest_api", name], [])}
}

api_gateway_with_invalid_compression_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_rest_api[name]
	not commonLib.between(resource.minimum_compression_size, 0, 10485759)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("Attribute 'minimum_compression_size' is %d", [resource.minimum_compression_size]), "keyExpectedValue": "Attribute 'minimum_compression_size' should be greater than -1 and smaller than 10485760", "remediation": json.marshal({"after": "0", "before": sprintf("%d", [resource.minimum_compression_size])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_rest_api", "searchKey": sprintf("aws_api_gateway_rest_api[%s].minimum_compression_size", [name]), "searchLine": commonLib.build_search_line(["resource", "aws_api_gateway_rest_api", name, "minimum_compression_size"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway With Invalid Compression"
# description: >-
#   API Gateway should have valid compression, which means attribute 'minimum_compression_size' should be set and its value should be greater than -1 and smaller than 10485760.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_with_invalid_compression"
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
api_gateway_with_invalid_compression_snippet[violation] {
	api_gateway_with_invalid_compression_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
