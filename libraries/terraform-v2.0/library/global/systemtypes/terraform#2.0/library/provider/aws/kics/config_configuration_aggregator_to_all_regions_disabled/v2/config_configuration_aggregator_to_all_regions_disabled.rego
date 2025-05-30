package global.systemtypes["terraform:2.0"].library.provider.aws.kics.config_configuration_aggregator_to_all_regions_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

config_configuration_aggregator_to_all_regions_disabled_inner[result] {
	resource := input.document[i].resource.aws_config_configuration_aggregator[name]
	resource[type].all_regions != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_config_configuration_aggregator[%s].%s.all_regions' is set to false", [name, type]), "keyExpectedValue": sprintf("'aws_config_configuration_aggregator[%s].%s.all_regions' should be set to true", [name, type]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_config_configuration_aggregator", "searchKey": sprintf("aws_config_configuration_aggregator[%s].%s.all_regions", [name, type]), "searchLine": common_lib.build_search_line(["resource", "aws_config_configuration_aggregator", name, type, "all_regions"], [])}
}

config_configuration_aggregator_to_all_regions_disabled_inner[result] {
	resource := input.document[i].resource.aws_config_configuration_aggregator[name]
	options := {"account_aggregation_source", "organization_aggregation_source"}
	type := options[o]
	resourceElement := resource[type]
	not common_lib.valid_key(resourceElement, "all_regions")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'aws_config_configuration_aggregator[%s].%s.all_regions' is undefined", [name, type]), "keyExpectedValue": sprintf("'aws_config_configuration_aggregator[%s].%s.all_regions' should be set to true", [name, type]), "remediation": "all_regions = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_config_configuration_aggregator", "searchKey": sprintf("aws_config_configuration_aggregator[%s].%s", [name, type]), "searchLine": common_lib.build_search_line(["resource", "aws_config_configuration_aggregator", name, type], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Configuration Aggregator to All Regions Disabled"
# description: >-
#   AWS Config Configuration Aggregator All Regions must be set to True
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.config_configuration_aggregator_to_all_regions_disabled"
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
#       identifier: aws_config_configuration_aggregator
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
config_configuration_aggregator_to_all_regions_disabled_snippet[violation] {
	config_configuration_aggregator_to_all_regions_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
