package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_deployment_without_access_log_setting.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_deployment_without_access_log_setting_inner[result] {
	document := input.document[i]
	deployment = document.resource.aws_api_gateway_deployment[name]
	count({x | resource := input.document[_0].resource[x]; x == "aws_api_gateway_stage"}) == 0
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_api_gateway_deployment[%s] doesn't have a 'aws_api_gateway_stage' resource associated", [name]), "keyExpectedValue": sprintf("aws_api_gateway_deployment[%s] has a 'aws_api_gateway_stage' resource associated", [name]), "resourceName": tf_lib.get_resource_name(deployment, name), "resourceType": "aws_api_gateway_deployment", "searchKey": sprintf("aws_api_gateway_deployment[%s]", [name])}
}

api_gateway_deployment_without_access_log_setting_inner[result] {
	document := input.document[i]
	deployment = document.resource.aws_api_gateway_deployment[name]
	count({x | resource := input.document[_0].resource[x]; x == "aws_api_gateway_stage"}) != 0
	not settings_are_equal(name)
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_api_gateway_deployment[%s] doesn't have a 'aws_api_gateway_stage' resource associated with 'access_log_settings' set", [name]), "keyExpectedValue": sprintf("aws_api_gateway_deployment[%s] has a 'aws_api_gateway_stage' resource associated with 'access_log_settings' set", [name]), "resourceName": tf_lib.get_resource_name(deployment, name), "resourceType": "aws_api_gateway_deployment", "searchKey": sprintf("aws_api_gateway_deployment[%s]", [name])}
}

api_gateway_deployment_without_access_log_setting_inner[result] {
	document := input.document[i]
	deployment = document.resource.aws_api_gateway_deployment[name]
	count({x | resource := input.document[_0].resource[x]; x == "aws_api_gateway_stage"}) != 0
	settings_are_equal(name)
	not common_lib.valid_key(deployment, "stage_description")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_api_gateway_deployment[%s].stage_description is undefined", [name]), "keyExpectedValue": sprintf("aws_api_gateway_deployment[%s].stage_description should be set", [name]), "resourceName": tf_lib.get_resource_name(deployment, name), "resourceType": "aws_api_gateway_deployment", "searchKey": sprintf("aws_api_gateway_deployment[%s]", [name])}
}

settings_are_equal(name) {
	count({x |
		stage := input.document[_].resource[x]
		x == "aws_api_gateway_stage"
		has_reference(stage[y].deployment_id, name)
		has_access_log_settings(stage[y])
	}) != 0
}

has_reference(deploymentId, name) {
	expected := sprintf("aws_api_gateway_deployment.%s.id", [name])
	contains(deploymentId, expected) == true
}

has_access_log_settings(resource) {
	common_lib.valid_key(resource, "access_log_settings")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway Deployment Without Access Log Setting"
# description: >-
#   API Gateway Deployment should have access log setting defined when connected to an API Gateway Stage.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_deployment_without_access_log_setting"
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
#       identifier: aws_api_gateway_deployment
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
api_gateway_deployment_without_access_log_setting_snippet[violation] {
	api_gateway_deployment_without_access_log_setting_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
