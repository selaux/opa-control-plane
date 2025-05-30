package global.systemtypes["terraform:2.0"].library.provider.aws.kics.hardcoded_aws_access_key_in_lambda.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

hardcoded_aws_access_key_in_lambda_inner[result] {
	resource := input.document[i].resource.aws_lambda_function[name]
	vars := resource.environment.variables
	re_match("(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}", vars[idx])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'environment.variables' contains AWS Access Key", "keyExpectedValue": "'environment.variables' shouldn't contain AWS Access Key", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_lambda_function", "searchKey": sprintf("aws_lambda_function[%s].environment.variables.%s", [name, idx]), "searchLine": common_lib.build_search_line(["resource", "aws_lambda_function", name, "environment", "variables", idx], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Hardcoded AWS Access Key In Lambda"
# description: >-
#   Lambda access/secret keys should not be hardcoded
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.hardcoded_aws_access_key_in_lambda"
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
#       identifier: aws_lambda_function
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
hardcoded_aws_access_key_in_lambda_snippet[violation] {
	hardcoded_aws_access_key_in_lambda_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
