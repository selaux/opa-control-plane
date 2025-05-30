package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_stage_without_api_gateway_usage_plan_associated.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_stage_without_api_gateway_usage_plan_associated_inner[result] {
	document := input.document[i]
	stage = document.resource.aws_api_gateway_stage[name]
	not settings_are_equal(document.resource, stage.rest_api_id, stage.stage_name)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_api_gateway_stage[%s] doesn't have a 'aws_api_gateway_usage_plan' resource associated.", [name]), "keyExpectedValue": sprintf("aws_api_gateway_stage[%s] has a 'aws_api_gateway_usage_plan' resource associated. ", [name]), "resourceName": tf_lib.get_resource_name(stage, name), "resourceType": "aws_api_gateway_stage", "searchKey": sprintf("aws_api_gateway_stage[%s]", [name])}
}

settings_are_equal(resource, rest_api_id, stage_name) {
	usage_plan := resource.aws_api_gateway_usage_plan[_]
	usage_plan.api_stages.api_id == rest_api_id
	usage_plan.api_stages.stage == stage_name
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway Stage Without API Gateway UsagePlan Associated"
# description: >-
#   API Gateway Stage should have API Gateway UsagePlan defined and associated.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_stage_without_api_gateway_usage_plan_associated"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
api_gateway_stage_without_api_gateway_usage_plan_associated_snippet[violation] {
	api_gateway_stage_without_api_gateway_usage_plan_associated_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
