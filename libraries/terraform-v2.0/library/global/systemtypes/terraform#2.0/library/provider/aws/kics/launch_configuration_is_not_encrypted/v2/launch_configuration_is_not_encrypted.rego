package global.systemtypes["terraform:2.0"].library.provider.aws.kics.launch_configuration_is_not_encrypted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

launch_configuration_is_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_launch_configuration[name]
	resource[block].encrypted == false
	valid_block(block)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_launch_configuration[%s].%s.encrypted is false", [name, block]), "keyExpectedValue": sprintf("aws_launch_configuration[%s].%s.encrypted should be true", [name, block]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_launch_configuration", "searchKey": sprintf("aws_launch_configuration[%s].%s.encrypted", [name, block]), "searchLine": common_lib.build_search_line(["resource", "aws_launch_configuration", name, block, "encrypted"], [])}
}

launch_configuration_is_not_encrypted_inner[result] {
	resource := input.document[i].resource.aws_launch_configuration[name]
	resourceBlock := resource[block]
	not common_lib.valid_key(resourceBlock, "encrypted")
	valid_block(block)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("aws_launch_configuration[%s].%s.encrypted is undefined", [name, block]), "keyExpectedValue": sprintf("aws_launch_configuration[%s].%s.encrypted should be set", [name, block]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_launch_configuration", "searchKey": sprintf("aws_launch_configuration[%s].%s", [name, block]), "searchLine": common_lib.build_search_line(["resource", "aws_launch_configuration", name, block], [])}
}

launch_configuration_is_not_encrypted_inner[result] {
	module := input.document[i].module[name]
	[path, value] := walk(module)
	value[block][idx].encrypted == false
	common_lib.get_module_equivalent_key("aws", module.source, "aws_launch_configuration", block)
	valid_block(block)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'encrypted' is false", "keyExpectedValue": "'encrypted' should be true", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s.encrypted", [name, block]), "searchLine": common_lib.build_search_line(["module", name, block, idx], ["encrypted"])}
}

launch_configuration_is_not_encrypted_inner[result] {
	module := input.document[i].module[name]
	[path, value] := walk(module)
	v := value[block][idx]
	not common_lib.valid_key(v, "encrypted")
	common_lib.get_module_equivalent_key("aws", module.source, "aws_launch_configuration", block)
	valid_block(block)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'encrypted' is undefined", "keyExpectedValue": "'encrypted' should be set", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].%s", [name, block]), "searchLine": common_lib.build_search_line(["module", name, block], [idx])}
}

valid_block(block) {
	not contains(block, "ephemeral")
	contains(block, "block_device")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Launch Configuration Is Not Encrypted"
# description: >-
#   Launch Configurations should have the data in the volumes encrypted. To encrypt the data, the 'encrypted' parameter should be set to true in each volume
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.launch_configuration_is_not_encrypted"
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
#       identifier: aws_launch_configuration
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
launch_configuration_is_not_encrypted_snippet[violation] {
	launch_configuration_is_not_encrypted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
