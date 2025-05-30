package global.systemtypes["terraform:2.0"].library.provider.azure.kics.small_postgresql_db_server_log_retention_period.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

small_postgresql_db_server_log_retention_period_inner[result] {
	config := input.document[i].resource.azurerm_postgresql_configuration[name]
	config.name == "log_retention_days"
	not commonLib.between(to_number(config.value), 4, 7)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_postgresql_configuration[%s].value' is %s", [name, config.value]), "keyExpectedValue": sprintf("'azurerm_postgresql_configuration[%s].value' is greater than 3 and less than 8", [name]), "remediation": json.marshal({"after": "7", "before": sprintf("%d", [config.value])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(config, name), "resourceType": "azurerm_postgresql_configuration", "searchKey": sprintf("azurerm_postgresql_configuration[%s].value", [name]), "searchLine": commonLib.build_search_line(["resource", "azurerm_postgresql_configuration", name, "value"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Small PostgreSQL DB Server Log Retention Period"
# description: >-
#   Check if PostgreSQL Database Server retains logs for less than 3 Days
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.small_postgresql_db_server_log_retention_period"
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
#     name: "azurerm"
#     versions:
#       min: "v2"
#       max: "v3"
#   rule_targets:
#     - argument: ""
#       identifier: azurerm_postgresql_configuration
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
small_postgresql_db_server_log_retention_period_snippet[violation] {
	small_postgresql_db_server_log_retention_period_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
