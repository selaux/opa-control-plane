package global.systemtypes["terraform:2.0"].library.provider.aws.kics.iam_policy_grants_assumerole_permission_across_all_services.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

iam_policy_grants_assumerole_permission_across_all_services_inner[result] {
	resource := input.document[i].resource.aws_iam_role[name]
	re_match("Service", resource.assume_role_policy)
	policy := common_lib.json_unmarshal(resource.assume_role_policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'assume_role_policy.Statement.Principal' contains '*'", "keyExpectedValue": "'assume_role_policy.Statement.Principal' shouldn't contain '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_iam_role", "searchKey": sprintf("aws_iam_role[%s].assume_role_policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_iam_role", name, "assume_role_policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IAM Policy Grants 'AssumeRole' Permission Across All Services"
# description: >-
#   IAM Policy should not grant 'AssumeRole' permission across all services.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.iam_policy_grants_assumerole_permission_across_all_services"
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
#       identifier: aws_iam_role
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
iam_policy_grants_assumerole_permission_across_all_services_snippet[violation] {
	iam_policy_grants_assumerole_permission_across_all_services_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
