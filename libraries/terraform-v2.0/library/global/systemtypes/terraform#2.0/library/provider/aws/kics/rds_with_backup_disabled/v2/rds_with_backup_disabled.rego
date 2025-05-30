package global.systemtypes["terraform:2.0"].library.provider.aws.kics.rds_with_backup_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

rds_with_backup_disabled_inner[result] {
	db := input.document[i].resource.aws_db_instance[name]
	not common_lib.valid_key(db, "backup_retention_period")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'backup_retention_period' is not defined", "keyExpectedValue": "'backup_retention_period' should be defined, and bigger than '0'", "remediation": "backup_retention_period = 12", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(db, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name], [])}
}

rds_with_backup_disabled_inner[result] {
	db := input.document[i].resource.aws_db_instance[name]
	db.backup_retention_period == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'backup_retention_period' is equal '0'", "keyExpectedValue": "'backup_retention_period' should not equal '0'", "remediation": json.marshal({"after": "12", "before": "0"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(db, name), "resourceType": "aws_db_instance", "searchKey": sprintf("aws_db_instance[%s].backup_retention_period", [name]), "searchLine": common_lib.build_search_line(["resource", "aws_db_instance", name, "backup_retention_period"], [])}
}

rds_with_backup_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "backup_retention_period")
	module[keyToCheck] == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'backup_retention_period' is equal '0'", "keyExpectedValue": "'backup_retention_period' should not equal '0'", "remediation": json.marshal({"after": "12", "before": "0"}), "remediationType": "replacement", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s].backup_retention_period", [name]), "searchLine": common_lib.build_search_line(["module", name, "backup_retention_period"], [])}
}

rds_with_backup_disabled_inner[result] {
	module := input.document[i].module[name]
	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_db_instance", "backup_retention_period")
	not module[keyToCheck]
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'backup_retention_period' is not defined", "keyExpectedValue": "'backup_retention_period' should be defined, and bigger than '0'", "remediation": "backup_retention_period = 12", "remediationType": "addition", "resourceName": "n/a", "resourceType": "n/a", "searchKey": sprintf("module[%s]", [name]), "searchLine": common_lib.build_search_line(["module", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: RDS With Backup Disabled"
# description: >-
#   Make sure the AWS RDS configuration has automatic backup configured. If the retention period is equal to 0 there is no backup
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.rds_with_backup_disabled"
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
rds_with_backup_disabled_snippet[violation] {
	rds_with_backup_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
