package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sqs_queue_exposed.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sqs_queue_exposed_inner[result] {
	resource := input.document[i].resource.aws_sqs_queue[name]
	exposed(resource.policy)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.aws_sqs_queue[%s].policy.Principal does get the queue publicly accessible", [name]), "keyExpectedValue": sprintf("resource.aws_sqs_queue[%s].policy.Principal shouldn't get the queue publicly accessible", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sqs_queue", "searchKey": sprintf("aws_sqs_queue[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_sqs_queue", name, "policy"], [])}
}

sqs_queue_exposed_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_sqs_queue", "policy")
	exposed(module[keyToCheck])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'policy.Principal' does get the queue publicly accessible", "keyExpectedValue": "'policy.Principal' shouldn't get the queue publicly accessible", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name, "policy"], [])}
}

exposed(policyValue) {
	policy := common_lib.json_unmarshal(policyValue)
	st := common_lib.get_statement(policy)
	statement := st[_]

	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQS Queue Exposed"
# description: >-
#   Checks if the SQS Queue is exposed
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sqs_queue_exposed"
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
#       identifier: aws_sqs_queue
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
sqs_queue_exposed_snippet[violation] {
	sqs_queue_exposed_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
