package global.systemtypes["terraform:2.0"].library.provider.aws.kics.workspaces_workspace_volume_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

workspaces_workspace_volume_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_workspaces_workspace[name]
	volumes := get_volumes(resource.workspace_properties)
	volumesKey := volumes[n].key
	not common_lib.valid_key(resource, volumesKey)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_workspaces_workspace.%s is missing", [volumesKey]), "keyExpectedValue": sprintf("aws_workspaces_workspace.%s should be set to true", [volumesKey]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_workspaces_workspace", "searchKey": sprintf("aws_workspaces_workspace[{{%s}}].workspace_properties.%s", [name, volumes[n].value])}
}

workspaces_workspace_volume_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_workspaces_workspace[name]
	volumes := get_volumes(resource.workspace_properties)
	resource[volumes[n].key] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_workspaces_workspace.%s is set to false", [volumes[n].key]), "keyExpectedValue": sprintf("aws_workspaces_workspace.%s should be set to true", [volumes[n].key]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_workspaces_workspace", "searchKey": sprintf("aws_workspaces_workspace[{{%s}}].%s", [name, volumes[n].key])}
}

get_volumes(resource) = volumes {
	volume_size := {"user_volume_encryption_enabled": "user_volume_size_gib", "root_volume_encryption_enabled": "root_volume_size_gib"}
	volumes := {x | common_lib.valid_key(resource, volume_size[v]); x := {"key": v, "value": volume_size[v]}}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Workspaces Workspace Volume Not Encrypted"
# description: >-
#   AWS Workspaces Workspace data stored in volumes should be encrypted
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.workspaces_workspace_volume_not_encrypted"
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
#       identifier: aws_workspaces_workspace
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
workspaces_workspace_volume_not_encrypted_snippet[violation] {
	workspaces_workspace_volume_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
