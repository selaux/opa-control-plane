package global.systemtypes["terraform:2.0"].library.provider.aws.kics.rds_without_logging.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

rds_without_logging_inner[result] {
	db := input.document[i].resource.aws_db_instance[name]
	not db.enabled_cloudwatch_logs_exports
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'enabled_cloudwatch_logs_exports' is undefined", "keyExpectedValue": "'enabled_cloudwatch_logs_exports' should be defined", "resourceName": tf_lib.get_resource_name(db, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name], [])}
}

rds_without_logging_inner[result] {
	db := input.document[i].resource.aws_db_instance[name]
	count(db.enabled_cloudwatch_logs_exports) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'enabled_cloudwatch_logs_exports' is empty", "keyExpectedValue": "'enabled_cloudwatch_logs_exports' has one or more values", "resourceName": tf_lib.get_resource_name(db, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s].enabled_cloudwatch_logs_exports", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name, "enabled_cloudwatch_logs_exports"], [])}
}

rds_without_logging_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "enabled_cloudwatch_logs_exports")
	not module[keyToCheck]
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'enabled_cloudwatch_logs_exports' is undefined", "keyExpectedValue": "'enabled_cloudwatch_logs_exports' should be defined", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

rds_without_logging_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "enabled_cloudwatch_logs_exports")
	count(module[keyToCheck]) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'enabled_cloudwatch_logs_exports' is empty", "keyExpectedValue": "'enabled_cloudwatch_logs_exports' has one or more values", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].enabled_cloudwatch_logs_exports", [name]), "searchLine": common_lib.build_search_line(["module", name, "enabled_cloudwatch_logs_exports"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: RDS Without Logging"
# description: >-
#   RDS does not have any kind of logger
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.rds_without_logging"
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
rds_without_logging_snippet[violation] {
	rds_without_logging_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
