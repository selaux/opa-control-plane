package global.systemtypes["terraform:2.0"].library.provider.aws.kics.sns_topic_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

sns_topic_is_publicly_accessible_inner[result] {
	resource := input.document[i].resource.aws_sns_topic[name]
	policy := common_lib.json_unmarshal(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]
	common_lib.is_allow_effect(statement)
	tf_lib.anyPrincipal(statement)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'Statement.Principal.AWS' contains '*'", "keyExpectedValue": "'Statement.Principal.AWS' shouldn't contain '*'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_sns_topic", "searchKey": sprintf("aws_sns_topic[%s].policy", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_sns_topic", name, "policy"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SNS Topic is Publicly Accessible"
# description: >-
#   SNS Topic Policy should not allow any principal to access
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.sns_topic_is_publicly_accessible"
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
#       identifier: aws_sns_topic
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
sns_topic_is_publicly_accessible_snippet[violation] {
	sns_topic_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
