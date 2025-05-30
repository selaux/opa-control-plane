package global.systemtypes["terraform:2.0"].library.provider.aws.kics.kms_key_with_vulnerable_policy.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

kms_key_with_vulnerable_policy_inner[result] {
	resource := input.document[i].resource.aws_kms_key[name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	not common_lib.valid_key(statement, "Condition")
	common_lib.has_wildcard(statement, "kms:*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_kms_key[%s].policy has wildcard in 'Action' or 'Principal'", [name]), "keyExpectedValue": sprintf("aws_kms_key[%s].policy should not have wildcard in 'Action' and 'Principal'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kms_key", "searchKey": sprintf("aws_kms_key[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_kms_key", name, "policy"], [])}
}

kms_key_with_vulnerable_policy_inner[result] {
	resource := input.document[i].resource.aws_kms_key[name]
	not common_lib.valid_key(resource, "policy")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_kms_key[%s].policy is undefined or null", [name]), "keyExpectedValue": sprintf("aws_kms_key[%s].policy should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_kms_key", "searchKey": sprintf("aws_kms_key[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_kms_key", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: KMS Key With Vulnerable Policy"
# description: >-
#   Checks if the policy is vulnerable and needs updating.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.kms_key_with_vulnerable_policy"
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
#       identifier: aws_kms_key
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
kms_key_with_vulnerable_policy_snippet[violation] {
	kms_key_with_vulnerable_policy_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
