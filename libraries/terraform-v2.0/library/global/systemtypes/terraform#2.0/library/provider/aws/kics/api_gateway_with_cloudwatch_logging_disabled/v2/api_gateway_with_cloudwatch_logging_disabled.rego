package global.systemtypes["terraform:2.0"].library.provider.aws.kics.api_gateway_with_cloudwatch_logging_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

api_gateway_with_cloudwatch_logging_disabled_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_stage[name]
	not haveLogs(resource.stage_name)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'aws_cloudwatch_log_group' for the stage is not undefined or not using the correct naming convention", "keyExpectedValue": "'aws_cloudwatch_log_group' should be defined and use the correct naming convention", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_stage", "searchKey": sprintf("aws_api_gateway_stage[%s]", [name])}
}

haveLogs(stageName) {
	log := input.document[i].resource.aws_cloudwatch_log_group[_]
	regexPattern := sprintf("API-Gateway-Execution-Logs_\\${aws_api_gateway_rest_api\\.\\w+\\.id}/%s$", [stageName])
	regex.match(regexPattern, log.name)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: API Gateway With CloudWatch Logging Disabled"
# description: >-
#   AWS CloudWatch Logs for APIs should be enabled and using the naming convention described in documentation
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.api_gateway_with_cloudwatch_logging_disabled"
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
api_gateway_with_cloudwatch_logging_disabled_snippet[violation] {
	api_gateway_with_cloudwatch_logging_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
