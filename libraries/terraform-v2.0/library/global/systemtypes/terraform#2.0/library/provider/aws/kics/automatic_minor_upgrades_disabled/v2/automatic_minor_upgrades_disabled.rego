package global.systemtypes["terraform:2.0"].library.provider.aws.kics.automatic_minor_upgrades_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

automatic_minor_upgrades_disabled_inner[result] {
	resource := input.document[i].resource.aws_db_instance[name]
	resource.auto_minor_version_upgrade == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'auto_minor_version_upgrade' is set to false", "keyExpectedValue": "'auto_minor_version_upgrade' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s].auto_minor_version_upgrade", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name, "auto_minor_version_upgrade"], [])}
}

automatic_minor_upgrades_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "auto_minor_version_upgrade")
	module[keyToCheck] == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'auto_minor_version_upgrade' is set to false", "keyExpectedValue": "'auto_minor_version_upgrade' should be set to true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].auto_minor_version_upgrade", [name]), "searchLine": common_lib.build_search_line(["module", name, "auto_minor_version_upgrade"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Automatic Minor Upgrades Disabled"
# description: >-
#   RDS instance should have automatic minor upgrades enabled, which means the attribute 'auto_minor_version_upgrade' must be set to true.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.automatic_minor_upgrades_disabled"
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
#       identifier: aws_db_instance
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
automatic_minor_upgrades_disabled_snippet[violation] {
	automatic_minor_upgrades_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
