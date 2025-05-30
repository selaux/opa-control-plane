package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sqs_policy_with_public_access.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sqs_policy_with_public_access_inner[result] {
	resource := input.document[i].resource.aws_sqs_queue_policy[name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	check_principal(statement.Principal, "*")
	tf_lib.anyPrincipal(statement)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Principal.AWS' is equal '*'", "keyExpectedValue": "'policy.Statement.Principal.AWS' should not equal '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sqs_queue_policy", "searchKey": sprintf("aws_sqs_queue_policy[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_sqs_queue_policy", name, "policy"], [])}
}

check_principal(field, value) {
	is_object(field)
	some i
	val := [x | x := field[i]; common_lib.containsOrInArrayContains(x, value)]
	count(val) > 0
} else {
	common_lib.containsOrInArrayContains(field, "*")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQS Policy With Public Access"
# description: >-
#   Checks for dangerous permissions in Action statements in an SQS Queue Policy. This is deemed a potential security risk as it would allow various attacks to the queue
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sqs_policy_with_public_access"
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
#       identifier: aws_sqs_queue_policy
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
sqs_policy_with_public_access_snippet[violation] {
	sqs_policy_with_public_access_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
