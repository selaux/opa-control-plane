package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sns_topic_publicity_has_allow_and_not_action_simultaneously.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sns_topic_publicity_has_allow_and_not_action_simultaneously_inner[result] {
	document := input.document[i]
	resources := {"aws_sns_topic", "aws_sns_topic_policy"}
	resource := document.resource[resources[r]][name]
	policy := resource.policy
	validate_json(policy)
	pol := common_lib.json_unmarshal(policy)
	st := common_lib.get_statement(pol)
	statement := st[_0]
	common_lib.is_allow_effect(statement)
	statement.NotAction
	result := {"documentId": document.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].policy has 'Effect: Allow' and 'NotAction' simultaneously", [resources[r], name]), "keyExpectedValue": sprintf("%s[%s].policy shouldn't have 'Effect: Allow' and 'NotAction' simultaneously", [resources[r], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resources[r], "searchKey": sprintf("%s[%s].policy", [resources[r], name]), "searchLine": common_lib.build_search_line(["resource", resources[r], name, "policy"], [])}
}

sns_topic_publicity_has_allow_and_not_action_simultaneously_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sns_topic_policy", "policy")
	policy := module[keyToCheck]
	validate_json(policy)
	pol := common_lib.json_unmarshal(policy)
	st := common_lib.get_statement(pol)
	statement := st[_0]
	common_lib.is_allow_effect(statement)
	statement.NotAction
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("module[%s].policy has 'Effect: Allow' and 'NotAction' simultaneously", [name]), "keyExpectedValue": sprintf("module[%s].policy shouldn't have 'Effect: Allow' and 'NotAction' simultaneously", [name]), "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].policy", [name]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck], [])}
}

validate_json(string) {
	not startswith(string, "$")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SNS Topic Publicity Has Allow and NotAction Simultaneously"
# description: >-
#   SNS topic Publicity should not have 'Effect: Allow' and argument 'NotAction' at the same time. If it has 'Effect: Allow', the argument stated should be 'Action'.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sns_topic_publicity_has_allow_and_not_action_simultaneously"
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
#       identifier: aws_sns_topic_policy
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
sns_topic_publicity_has_allow_and_not_action_simultaneously_snippet[violation] {
	sns_topic_publicity_has_allow_and_not_action_simultaneously_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
