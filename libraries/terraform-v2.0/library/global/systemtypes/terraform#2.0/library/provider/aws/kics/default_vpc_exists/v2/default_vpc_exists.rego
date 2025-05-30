package global.systemtypes["terraform:2.0"].library.provider.aws.kics.default_vpc_exists.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

default_vpc_exists_inner[result] {
	resource := input.document[i].resource.aws_default_vpc[name]
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'aws_default_vpc' exists", "keyExpectedValue": "'aws_default_vpc' should not exist", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_default_vpc", "searchKey": sprintf("aws_default_vpc[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_default_vpc", name], [])}
}

default_vpc_exists_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_default_vpc", "default_vpc_name")
	common_lib.valid_key(module, keyToCheck)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'aws_default_vpc' exists", "keyExpectedValue": "'aws_default_vpc' should not exist", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("%s.%s", [name, keyToCheck]), "searchLine": common_lib.build_search_line(["module", name, keyToCheck], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Default VPC Exists"
# description: >-
#   It isn't recommended to use resources in default VPC
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.default_vpc_exists"
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
default_vpc_exists_snippet[violation] {
	default_vpc_exists_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
