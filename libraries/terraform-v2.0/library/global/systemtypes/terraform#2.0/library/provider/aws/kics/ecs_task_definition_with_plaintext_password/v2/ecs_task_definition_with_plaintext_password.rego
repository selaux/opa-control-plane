package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ecs_task_definition_with_plaintext_password.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ecs_task_definition_with_plaintext_password_inner[result] {
	resource := input.document[i].resource.aws_ecs_task_definition[name]
	resourceJson := commonLib.json_unmarshal(resource.container_definitions)
	env := resourceJson.containerDefinitions[_].environment[_]
	contains(lower(env.name), "password")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'container_definitions.environment.name' has password value", "keyExpectedValue": "'container_definitions.environment.name' shouldn't have password value", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecs_task_definition", "searchKey": sprintf("%s", [env.name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ECS Task Definition Container With Plaintext Password"
# description: >-
#   It's not recommended to use plaintext environment variables for sensitive information, such as credential data.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ecs_task_definition_with_plaintext_password"
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
ecs_task_definition_with_plaintext_password_snippet[violation] {
	ecs_task_definition_with_plaintext_password_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
