package global.systemtypes["terraform:2.0"].library.provider.aws.kics.autoscaling_groups_supply_tags.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

autoscaling_groups_supply_tags_inner[result] {
	auto := input.document[i].resource.aws_autoscaling_group[name]
	not common_lib.valid_key(auto, "tags")
	not common_lib.valid_key(auto, "tag")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'tags' and 'tag' are undefined or null", "keyExpectedValue": "'tags' or 'tag' should be defined and not null", "resourceName": tf_lib.get_resource_name(auto, name), "resourceType": "aws_autoscaling_group", "searchKey": sprintf("aws_autoscaling_group[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], [])}
}

autoscaling_groups_supply_tags_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_autoscaling_group", "tags")
	not common_lib.valid_key(module, keyToCheck)
	tagsAsMap := common_lib.get_module_equivalent_key("aws", module.source, "aws_autoscaling_group", "tags_as_map")
	not common_lib.valid_key(module, tagsAsMap)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'tags' is undefined or null", "keyExpectedValue": "'tags' should be defined and not null", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Autoscaling Groups Supply Tags"
# description: >-
#   Autoscaling groups should supply tags to configurate
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.autoscaling_groups_supply_tags"
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
#       identifier: aws_autoscaling_group
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
autoscaling_groups_supply_tags_snippet[violation] {
	autoscaling_groups_supply_tags_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
