package global.systemtypes["terraform:2.0"].library.provider.aws.kics.lambda_permission_principal_is_wildcard.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

lambda_permission_principal_is_wildcard_inner[result] {
	document := input.document[i]
	resource := document.resource.aws_lambda_permission[name]
	contains(resource.principal, "*")
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_lambda_permission[%s].principal contains a wildcard", [name]), "keyExpectedValue": sprintf("aws_lambda_permission[%s].principal shouldn't contain a wildcard", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_lambda_permission", "searchKey": sprintf("aws_lambda_permission[%s].principal", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Lambda Permission Principal Is Wildcard"
# description: >-
#   Lambda Permission Principal should not contain a wildcard.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.lambda_permission_principal_is_wildcard"
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
lambda_permission_principal_is_wildcard_snippet[violation] {
	lambda_permission_principal_is_wildcard_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
