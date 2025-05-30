package global.systemtypes["terraform:2.0"].library.provider.aws.kics.cloudwatch_metrics_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

cloudwatch_metrics_disabled_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_method_settings[name].settings
	resource.metrics_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_api_gateway_method_settings[%s].settings.metrics_enabled is false", [name]), "keyExpectedValue": sprintf("aws_api_gateway_method_settings[%s].settings.metrics_enabled should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_method_settings", "searchKey": sprintf("aws_api_gateway_method_settings[%s].settings.metrics_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_method_settings", name, "settings", "metrics_enabled"], [])}
}

cloudwatch_metrics_disabled_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_method_settings[name].settings
	not common_lib.valid_key(resource, "metrics_enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_api_gateway_method_settings[%s].settings.metrics_enabled is undefined or null", [name]), "keyExpectedValue": sprintf("aws_api_gateway_method_settings[%s].settings.metrics_enabled should be defined and not null", [name]), "remediation": "metrics_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_method_settings", "searchKey": sprintf("aws_api_gateway_method_settings[%s].settings", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_method_settings", name, "settings"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CloudWatch Metrics Disabled"
# description: >-
#   Checks if CloudWatch Metrics is Enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.cloudwatch_metrics_disabled"
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
#       identifier: aws_api_gateway_method_settings
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
cloudwatch_metrics_disabled_snippet[violation] {
	cloudwatch_metrics_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
