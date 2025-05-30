package global.systemtypes["terraform:2.0"].library.provider.aws.kics.stack_without_template.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

stack_without_template_inner[result] {
	resource := input.document[i].resource.aws_cloudformation_stack[name]
	not common_lib.valid_key(resource, "template_body")
	not common_lib.valid_key(resource, "template_url")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Both Attribute 'template_body' and Attribute 'template_url' are undefined", "keyExpectedValue": "Attribute 'template_body' or Attribute 'template_url' should be set", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudformation_stack", "searchKey": sprintf("aws_cloudformation_stack[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Stack Without Template"
# description: >-
#   AWS CloudFormation should have a template defined through the attribute template_url or attribute template_body
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.stack_without_template"
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
#       identifier: aws_cloudformation_stack
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
stack_without_template_snippet[violation] {
	stack_without_template_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
