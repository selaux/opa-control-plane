package global.systemtypes["terraform:2.0"].library.provider.aws.kics.user_data_shell_script_is_encoded.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

user_data_shell_script_is_encoded_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_launch_configuration", "user_data_base64")
	common_lib.valid_key(module, "user_data_base64")
	decoded_result := base64.decode(module.user_data_base64)
	startswith(decoded_result, "#!/")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'user_data_base64' is defined", "keyExpectedValue": "'user_data_base64' should be undefined or not script", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name, "user_data_base64"], [])}
}

user_data_shell_script_is_encoded_inner[result] {
	resource := input.document[i].resource.aws_launch_configuration[name]
	common_lib.valid_key(resource, "user_data_base64")
	decoded_result := base64.decode(resource.user_data_base64)
	startswith(decoded_result, "#!/")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("aws_launch_configuration[%s].user_data_base64 is defined", [name]), "keyExpectedValue": sprintf("aws_launch_configuration[%s].user_data_base64 should be undefined or not script", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_launch_configuration", "searchKey": sprintf("aws_launch_configuration[%s].user_data_base64", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_launch_configuration", name, "user_data_base64"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: User Data Shell Script Is Encoded"
# description: >-
#   User Data Shell Script must be encoded
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.user_data_shell_script_is_encoded"
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
user_data_shell_script_is_encoded_snippet[violation] {
	user_data_shell_script_is_encoded_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
