package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_xray_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_xray_disabled_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_stage[name]
	resource.xray_tracing_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_api_gateway_stage[%s].xray_tracing_enabled' is false", [name]), "keyExpectedValue": sprintf("'aws_api_gateway_stage[%s].xray_tracing_enabled' should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_stage", "searchKey": sprintf("aws_api_gateway_stage[%s].xray_tracing_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_stage", name, "xray_tracing_enabled"], [])}
}

api_gateway_xray_disabled_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_stage[name]
	not common_lib.valid_key(resource, "xray_tracing_enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_api_gateway_stage[%s].xray_tracing_enabled' is undefined", [name]), "keyExpectedValue": sprintf("'aws_api_gateway_stage[%s].xray_tracing_enabled' should be set", [name]), "remediation": "xray_tracing_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_stage", "searchKey": sprintf("aws_api_gateway_stage[%s].xray_tracing_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_stage", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway X-Ray Disabled"
# description: >-
#   API Gateway should have X-Ray Tracing enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_xray_disabled"
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
api_gateway_xray_disabled_snippet[violation] {
	api_gateway_xray_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
