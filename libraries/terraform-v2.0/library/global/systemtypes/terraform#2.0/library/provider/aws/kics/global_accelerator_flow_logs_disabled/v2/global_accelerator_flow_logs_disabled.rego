package global.systemtypes["terraform:2.0"].library.provider.aws.kics.global_accelerator_flow_logs_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

global_accelerator_flow_logs_disabled_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_globalaccelerator_accelerator[name]
	not common_lib.valid_key(resource, "attributes")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_globalaccelerator_accelerator[{{%s}}].flow_logs_enabled is undefined or null", [name]), "keyExpectedValue": sprintf("aws_globalaccelerator_accelerator[{{%s}}].flow_logs_enabled should be defined and not null", [name]), "remediation": "attributes {\n\t\t flow_logs_enabled = true \n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_globalaccelerator_accelerator", "searchKey": sprintf("aws_globalaccelerator_accelerator[{{%s}}]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_globalaccelerator_accelerator", name], [])}
}

global_accelerator_flow_logs_disabled_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_globalaccelerator_accelerator[name].attributes
	not common_lib.valid_key(resource, "flow_logs_enabled")
	result := {"documentId": document.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_globalaccelerator_accelerator[{{%s}}].flow_logs_enabled is undefined or null", [name]), "keyExpectedValue": sprintf("aws_globalaccelerator_accelerator[{{%s}}].flow_logs_enabled should be defined and not null", [name]), "remediation": "flow_logs_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(document.resource.aws_globalaccelerator_accelerator[name], name), "resourceType": "aws_globalaccelerator_accelerator", "searchKey": sprintf("aws_globalaccelerator_accelerator[{{%s}}].attributes", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_globalaccelerator_accelerator", name, "attributes"], [])}
}

global_accelerator_flow_logs_disabled_inner[result] {
	document := input.document[i]
	logs := document.resource.aws_globalaccelerator_accelerator[name].attributes.flow_logs_enabled
	logs == false
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_globalaccelerator_accelerator[{{%s}}].flow_logs_enabled is false", [name]), "keyExpectedValue": sprintf("aws_globalaccelerator_accelerator[{{%s}}].flow_logs_enabled should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(document.resource.aws_globalaccelerator_accelerator[name], name), "resourceType": "aws_globalaccelerator_accelerator", "searchKey": sprintf("aws_globalaccelerator_accelerator[{{%s}}].attributes.flow_logs_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_globalaccelerator_accelerator", name, "attributes", "flow_logs_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Global Accelerator Flow Logs Disabled"
# description: >-
#   Global Accelerator should have flow logs enabled
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.global_accelerator_flow_logs_disabled"
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
#       identifier: aws_globalaccelerator_accelerator
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
global_accelerator_flow_logs_disabled_snippet[violation] {
	global_accelerator_flow_logs_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
