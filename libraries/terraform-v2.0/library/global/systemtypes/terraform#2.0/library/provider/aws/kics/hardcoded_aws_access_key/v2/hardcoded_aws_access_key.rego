package global.systemtypes["terraform:2.0"].library.provider.aws.kics.hardcoded_aws_access_key.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

hardcoded_aws_access_key_inner[result] {
	instance := input.document[i].resource.aws_instance[name]
	containsAccessKey(instance.user_data)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'user_data' contains hardcoded access key", "keyExpectedValue": "'user_data' shouldn't contain hardcoded access key", "resourceName": tf_lib.get_resource_name(instance, name), "resourceType": "aws_instance", "searchKey": sprintf("aws_instance[%s].user_data", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "user_data"], [])}
}

hardcoded_aws_access_key_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_instance", "user_data")
	containsAccessKey(module[keyToCheck])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'user_data' contains hardcoded access key", "keyExpectedValue": "'user_data' shouldn't contain hardcoded access key", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].user_data", [name]), "searchLine": common_lib.build_search_line(["module", name, "user_data"], [])}
}

containsAccessKey(user_data) {
	re_match("([^A-Z0-9])[A-Z0-9]{20}([^A-Z0-9])", user_data)
}

containsAccessKey(user_data) {
	re_match("[A-Za-z0-9/+=]{40}([^A-Za-z0-9/+=])", user_data)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Hardcoded AWS Access Key"
# description: >-
#   AWS Access Key should not be hardcoded
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.hardcoded_aws_access_key"
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
hardcoded_aws_access_key_snippet[violation] {
	hardcoded_aws_access_key_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
