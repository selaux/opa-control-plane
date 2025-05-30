package global.systemtypes["terraform:2.0"].library.provider.aws.kics.stack_retention_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

stack_retention_disabled_inner[result] {
	resource := input.document[i].resource
	stack := resource.aws_cloudformation_stack_set_instance[name]
	not common_lib.valid_key(stack, "retain_stack")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_cloudformation_stack_set_instance[%s].retain_stack is undefined or null", [name]), "keyExpectedValue": sprintf("aws_cloudformation_stack_set_instance[%s].retain_stack should be defined and not null", [name]), "remediation": "retain_stack = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudformation_stack_set_instance", "searchKey": sprintf("aws_cloudformation_stack_set_instance[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudformation_stack_set_instance", name], [])}
}

stack_retention_disabled_inner[result] {
	resource := input.document[i].resource
	stack := resource.aws_cloudformation_stack_set_instance[name]
	stack.retain_stack == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_cloudformation_stack_set_instance[%s].retain_stack is false", [name]), "keyExpectedValue": sprintf("aws_cloudformation_stack_set_instance[%s].retain_stack should be true ", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudformation_stack_set_instance", "searchKey": sprintf("aws_cloudformation_stack_set_instance[%s].retain_stack", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_cloudformation_stack_set_instance", name, "retain_stack"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Stack Retention Disabled"
# description: >-
#   Make sure that retain_stack is enabled to keep the Stack and it's associated resources during resource destruction
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.stack_retention_disabled"
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
#       identifier: aws_cloudformation_stack_set_instance
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
stack_retention_disabled_snippet[violation] {
	stack_retention_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
