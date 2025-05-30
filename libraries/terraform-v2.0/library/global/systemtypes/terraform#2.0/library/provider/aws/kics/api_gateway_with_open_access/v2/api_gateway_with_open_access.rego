package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_with_open_access.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_with_open_access_inner[result] {
	document := input.document[i]
	resource = document.resource.aws_api_gateway_method[name]
	resource.authorization == "NONE"
	resource.http_method != "OPTIONS"
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_api_gateway_method[%s].authorization type is 'NONE' and http_method is not ''OPTIONS'", [name]), "keyExpectedValue": "aws_api_gateway_method.authorization should only be 'NONE' if http_method is 'OPTIONS'", "remediation": json.marshal({"after": "OPTIONS", "before": sprintf("%s", [resource.http_method])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_method", "searchKey": sprintf("aws_api_gateway_method[%s].http_method", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_method", name, "http_method"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway With Open Access"
# description: >-
#   API Gateway Method should restrict the authorization type, except for the HTTP OPTIONS method.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_with_open_access"
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
api_gateway_with_open_access_snippet[violation] {
	api_gateway_with_open_access_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
