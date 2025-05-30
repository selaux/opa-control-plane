package global.systemtypes["terraform:2.0"].library.provider.aws.kics.ecs_task_definition_volume_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

ecs_task_definition_volume_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_ecs_task_definition[name]
	resource.volume.efs_volume_configuration.transit_encryption == "DISABLED"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "aws_ecs_task_definition.volume.efs_volume_configuration.transit_encryption value is 'DISABLED'", "keyExpectedValue": "aws_ecs_task_definition.volume.efs_volume_configuration.transit_encryption value should be 'ENABLED'", "remediation": json.marshal({"after": "ENABLED", "before": "DISABLED"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecs_task_definition", "searchKey": sprintf("aws_ecs_task_definition[{{%s}}].volume.efs_volume_configuration.transit_encryption", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ecs_task_definition", name, "volume", "efs_volume_configuration", "transit_encryption"], [])}
}

ecs_task_definition_volume_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_ecs_task_definition[name]
	enc := resource.volume.efs_volume_configuration
	not common_lib.valid_key(enc, "transit_encryption")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "aws_ecs_task_definition.volume.efs_volume_configuration.transit_encryption is missing", "keyExpectedValue": "aws_ecs_task_definition.volume.efs_volume_configuration.transit_encryption value should be 'ENABLED'", "remediation": "transit_encryption = \"ENABLED\"", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_ecs_task_definition", "searchKey": sprintf("aws_ecs_task_definition[{{%s}}].volume.efs_volume_configuration", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_ecs_task_definition", name, "volume", "efs_volume_configuration"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: ECS Task Definition Volume Not Encrypted"
# description: >-
#   AWS ECS Task Definition EFS data in transit between AWS ECS host and AWS EFS server should be encrypted
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.ecs_task_definition_volume_not_encrypted"
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
ecs_task_definition_volume_not_encrypted_snippet[violation] {
	ecs_task_definition_volume_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
