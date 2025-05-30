package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ecs_cluster_container_insights_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ecs_cluster_container_insights_disabled_inner[result] {
	resource := input.document[i].resource.aws_ecs_cluster[name]
	not container_insights_enabled(resource)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_ecs_cluster[%s].setting.name' is not set to 'containerInsights' and/or 'aws_ecs_cluster[%s].setting.value' is not set to 'enabled'", [name, name]), "keyExpectedValue": sprintf("'aws_ecs_cluster[%s].setting.name' should be set to 'containerInsights' and 'aws_ecs_cluster[%s].setting.value' should be set to 'enabled'", [name, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecs_cluster", "searchKey": sprintf("aws_ecs_cluster[%s]", [name])}
}

container_insights_enabled(resource) {
	resource.setting.value == "enabled"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ECS Cluster with Container Insights Disabled"
# description: >-
#   ECS Cluster should enable container insights
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ecs_cluster_container_insights_disabled"
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
#       identifier: aws_ecs_cluster
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
ecs_cluster_container_insights_disabled_snippet[violation] {
	ecs_cluster_container_insights_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
