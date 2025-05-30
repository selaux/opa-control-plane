package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.sql_db_instance_backup_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

sql_db_instance_backup_disabled_inner[result] {
	settings := input.document[i].resource.google_sql_database_instance[name].settings
	not common_lib.valid_key(settings, "backup_configuration")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "settings.backup_configuration is undefined or null", "keyExpectedValue": "settings.backup_configuration should be defined and not null", "resourceName": tf_lib.get_resource_name(input.document[i].resource.google_sql_database_instance[name], name), "resourceType": "google_sql_database_instance", "searchKey": sprintf("google_sql_database_instance[%s].settings", [name]), "searchLine": common_lib.build_search_line(["resource", "google_sql_database_instance", name], ["settings"])}
}

sql_db_instance_backup_disabled_inner[result] {
	settings := input.document[i].resource.google_sql_database_instance[name].settings.backup_configuration
	not common_lib.valid_key(settings, "enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "settings.backup_configuration.enabled is undefined or null", "keyExpectedValue": "settings.backup_configuration.enabled should be defined and not null", "remediation": "enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(input.document[i].resource.google_sql_database_instance[name], name), "resourceType": "google_sql_database_instance", "searchKey": sprintf("google_sql_database_instance[%s].settings.backup_configuration", [name]), "searchLine": common_lib.build_search_line(["resource", "google_sql_database_instance", name], ["settings", "backup_configuration"])}
}

sql_db_instance_backup_disabled_inner[result] {
	settings := input.document[i].resource.google_sql_database_instance[name].settings
	settings.backup_configuration.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "settings.backup_configuration.enabled is false", "keyExpectedValue": "settings.backup_configuration.enabled should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(input.document[i].resource.google_sql_database_instance[name], name), "resourceType": "google_sql_database_instance", "searchKey": sprintf("google_sql_database_instance[%s].settings.backup_configuration.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "google_sql_database_instance", name], ["settings", "backup_configuration", "enabled"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQL DB Instance Backup Disabled"
# description: >-
#   Checks if backup configuration is enabled for all Cloud SQL Database instances
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.sql_db_instance_backup_disabled"
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
#     name: "google"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: google_sql_database_instance
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
sql_db_instance_backup_disabled_snippet[violation] {
	sql_db_instance_backup_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
