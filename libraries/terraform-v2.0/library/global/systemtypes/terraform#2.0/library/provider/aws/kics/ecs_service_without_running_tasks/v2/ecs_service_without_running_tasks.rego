package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ecs_service_without_running_tasks.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ecs_service_without_running_tasks_inner[result] {
	resource := input.document[i].resource.aws_ecs_service[name]
	not checkContent(resource)
	checkDesiredCount(resource)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'aws_ecs_service[%s]' must have at least 1 task running", [name]), "keyExpectedValue": sprintf("'aws_ecs_service[%s]' has at least 1 task running", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecs_service", "searchKey": sprintf("aws_ecs_service[%s]", [name])}
}

checkContent(deploymentConfiguration) {
	common_lib.valid_key(deploymentConfiguration, "deployment_maximum_percent")
} else {
	common_lib.valid_key(deploymentConfiguration, "deployment_minimum_healthy_percent")
}

checkDesiredCount(deploymentConfiguration) {
	deploymentConfiguration.desired_count == 0
	getSchedulingStrategy(deploymentConfiguration) != "DAEMON"
}

getSchedulingStrategy(resource) = ss {
	common_lib.valid_key(resource, "scheduling_strategy")
	ss := resource.scheduling_strategy
} else = ss {
	ss := "REPLICA"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ECS Service Without Running Tasks"
# description: >-
#   ECS Service should have at least 1 task running
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ecs_service_without_running_tasks"
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
#       identifier: aws_ecs_service
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
ecs_service_without_running_tasks_snippet[violation] {
	ecs_service_without_running_tasks_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
