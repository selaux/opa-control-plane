package global.systemtypes["terraform:2.0"].library.provider.aws.kics.user_data_contains_encoded_private_key.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

decode_and_check_private_key(user_base64_data) {
	decoded_user_data := base64.decode(user_base64_data)
	regex.match(`-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`, decoded_user_data)
}

user_data_contains_encoded_private_key_inner[result] {
	resource := input.document[i].resource.aws_launch_configuration[name]
	user_data := resource.user_data_base64
	not user_data == null
	decode_and_check_private_key(user_data)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_launch_configuration[%s].user_data_base64 contains RSA Private Key", [name]), "keyExpectedValue": sprintf("aws_launch_configuration[%s].user_data_base64 shouldn't contain RSA Private Key", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_launch_configuration", "searchKey": sprintf("aws_launch_configuration[%s].user_data_base64", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_launch_configuration", name, "user_data_base64"], [])}
}

user_data_contains_encoded_private_key_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_launch_configuration", "user_data_base64")
	user_data := module.user_data_base64
	not user_data == null
	decode_and_check_private_key(user_data)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'user_data_base64' contains RSA Private Key", "keyExpectedValue": "'user_data_base64' shouldn't contain RSA Private Key", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].user_data_base64", [name]), "searchLine": common_lib.build_search_line(["module", name, "user_data_base64"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: User Data Contains Encoded Private Key"
# description: >-
#   User Data should not contain a base64 encoded private key. If so, anyone can decode the private key easily
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.user_data_contains_encoded_private_key"
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
user_data_contains_encoded_private_key_snippet[violation] {
	user_data_contains_encoded_private_key_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
