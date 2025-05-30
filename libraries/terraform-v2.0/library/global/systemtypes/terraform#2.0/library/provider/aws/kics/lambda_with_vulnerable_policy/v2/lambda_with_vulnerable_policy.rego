package global.systemtypes["terraform:2.0"].library.provider.aws.kics.lambda_with_vulnerable_policy.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

lambda_with_vulnerable_policy_inner[result] {
	resource := input.document[i].resource.aws_lambda_permission[name]
	resource.action == "lambda:*"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_lambda_permission[%s].action has wildcard", [name]), "keyExpectedValue": sprintf("aws_lambda_permission[%s].action should not have wildcard", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_lambda_permission", "searchKey": sprintf("aws_lambda_permission[%s].action", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Lambda With Vulnerable Policy"
# description: >-
#   The attribute 'action' should not have wildcard
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.lambda_with_vulnerable_policy"
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
#       identifier: aws_lambda_permission
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
lambda_with_vulnerable_policy_snippet[violation] {
	lambda_with_vulnerable_policy_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
