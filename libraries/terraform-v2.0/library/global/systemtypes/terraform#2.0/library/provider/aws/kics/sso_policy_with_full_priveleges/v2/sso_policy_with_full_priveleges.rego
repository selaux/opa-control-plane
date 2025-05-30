package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sso_policy_with_full_priveleges.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sso_policy_with_full_priveleges_inner[result] {
	resource := input.document[i].resource.aws_ssoadmin_permission_set_inline_policy[name]
	policy := common_lib.json_unmarshal(resource.inline_policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	common_lib.equalsOrInArray(statement.Resource, "*")
	common_lib.equalsOrInArray(statement.Action, "*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "inline_policy.Statement.Action is equal to or contains '*'", "keyExpectedValue": "inline_policy.Statement.Action should not equal to, nor contain '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ssoadmin_permission_set_inline_policy", "searchKey": sprintf("aws_ssoadmin_permission_set_inline_policy[%s].inline_policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ssoadmin_permission_set_inline_policy", name, "inline_policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SSO Policy with full privileges"
# description: >-
#   SSO policies should be configured to grant limited administrative privileges, rather than full access to all resources. This approach allows for better security and control over the resources being accessed.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sso_policy_with_full_priveleges"
#   impact: ""
#   remediation: ""
#   severity: "high"
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
#       identifier: aws_ssoadmin_permission_set_inline_policy
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
sso_policy_with_full_priveleges_snippet[violation] {
	sso_policy_with_full_priveleges_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
