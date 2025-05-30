package global.systemtypes["terraform:2.0"].library.provider.aws.kics.rest_api_with_vulnerable_policy.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

rest_api_with_vulnerable_policy_inner[result] {
	resource := input.document[i].resource.aws_api_gateway_rest_api_policy[name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	not common_lib.valid_key(statement, "Condition")
	common_lib.has_wildcard(statement, "execute-api:*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_api_gateway_rest_api_policy[%s].policy has wildcard in 'Action' or 'Principal'", [name]), "keyExpectedValue": sprintf("aws_api_gateway_rest_api_policy[%s].policy should not have wildcard in 'Action' and 'Principal'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_api_gateway_rest_api_policy", "searchKey": sprintf("aws_api_gateway_rest_api_policy[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_api_gateway_rest_api_policy", name, "policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: REST API With Vulnerable Policy"
# description: >-
#   REST API policy should avoid wildcard in 'Action' and 'Principal'
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.rest_api_with_vulnerable_policy"
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
rest_api_with_vulnerable_policy_snippet[violation] {
	rest_api_with_vulnerable_policy_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
