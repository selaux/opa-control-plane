package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ecs_task_definition_network_mode_not_recommended.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ecs_task_definition_network_mode_not_recommended_inner[result] {
	resource := input.document[i].resource.aws_ecs_task_definition[name]
	lower(resource.network_mode) != "awsvpc"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'network_mode' is equal to '%s'", [resource.network_mode]), "keyExpectedValue": "'network_mode' should equal to 'awsvpc'", "remediation": json.marshal({"after": "awsvpc", "before": sprintf("%s", [resource.network_mode])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecs_task_definition", "searchKey": sprintf("aws_ecs_task_definition[%s].network_mode", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ecs_task_definition", name, "network_mode"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ECS Task Definition Network Mode Not Recommended"
# description: >-
#   Network_Mode should be 'awsvpc' in ecs_task_definition. AWS VPCs provides the controls to facilitate a formal process for approving and testing all network connections and changes to the firewall and router configurations
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ecs_task_definition_network_mode_not_recommended"
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
#       identifier: aws_ecs_task_definition
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
ecs_task_definition_network_mode_not_recommended_snippet[violation] {
	ecs_task_definition_network_mode_not_recommended_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
