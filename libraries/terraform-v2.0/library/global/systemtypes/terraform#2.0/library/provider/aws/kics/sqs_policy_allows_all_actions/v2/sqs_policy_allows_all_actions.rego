package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sqs_policy_allows_all_actions.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sqs_policy_allows_all_actions_inner[result] {
	resource := input.document[i].resource.aws_sqs_queue_policy[name]
	tf_lib.allows_action_from_all_principals(resource.policy, "*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Action' is equal '*'", "keyExpectedValue": "'policy.Statement.Action' should not equal '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sqs_queue_policy", "searchKey": sprintf("aws_sqs_queue_policy[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_sqs_queue_policy", name, "policy"], [])}
}

sqs_policy_allows_all_actions_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sqs_queue_policy", "policy")
	tf_lib.allows_action_from_all_principals(module[keyToCheck], "*")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Statement.Action' is equal '*'", "keyExpectedValue": "'policy.Statement.Action' should not equal '*'", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQS Policy Allows All Actions"
# description: >-
#   SQS policy allows ALL (*) actions
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sqs_policy_allows_all_actions"
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
sqs_policy_allows_all_actions_snippet[violation] {
	sqs_policy_allows_all_actions_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
