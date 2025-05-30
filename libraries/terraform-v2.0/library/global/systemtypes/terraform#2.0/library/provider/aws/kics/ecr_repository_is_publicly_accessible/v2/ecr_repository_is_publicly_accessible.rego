package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ecr_repository_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ecr_repository_is_publicly_accessible_inner[result] {
	resource := input.document[i].resource.aws_ecr_repository_policy[name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'Statement.Principal' contains '*'", "keyExpectedValue": "'Statement.Principal' shouldn't contain '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecr_repository_policy", "searchKey": sprintf("aws_ecr_repository_policy[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ecr_repository_policy", name, "policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ECR Repository Is Publicly Accessible"
# description: >-
#   Amazon ECR image repositories shouldn't have public access
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ecr_repository_is_publicly_accessible"
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
#       identifier: aws_ecr_repository_policy
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
ecr_repository_is_publicly_accessible_snippet[violation] {
	ecr_repository_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
