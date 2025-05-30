package global.systemtypes["terraform:2.0"].library.provider.aws.kics.no_stack_policy.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

no_stack_policy_inner[result] {
	resource := input.document[i].resource.aws_cloudformation_stack[name]
	not resource.policy_body
	not resource.policy_url
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Both Attribute 'policy_body' and Attribute 'policy_url' are undefined", "keyExpectedValue": "Attribute 'policy_body' or Attribute 'policy_url' should be set", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_cloudformation_stack", "searchKey": sprintf("aws_cloudformation_stack[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: No Stack Policy"
# description: >-
#   AWS CloudFormation Stack should have a stack policy in order to protect stack resources from update actions
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.no_stack_policy"
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
no_stack_policy_snippet[violation] {
	no_stack_policy_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
