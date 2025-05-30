package global.systemtypes["terraform:2.0"].library.provider.azure.kics.postgre_sql_server_without_connection_throttling.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

postgre_sql_server_without_connection_throttling_inner[result] {
	resource := input.document[i].resource.azurerm_postgresql_configuration[var0]
	is_string(resource.name)
	name := lower(resource.name)
	is_string(resource.value)
	value := upper(resource.value)
	name == "connection_throttling"
	value != "ON"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_postgresql_configuration.%s.value' is 'OFF'", [var0]), "keyExpectedValue": sprintf("'azurerm_postgresql_configuration.%s.value' should be 'ON'", [var0]), "remediation": json.marshal({"after": "ON", "before": sprintf("%s", [resource.value])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_postgresql_configuration", "searchKey": sprintf("azurerm_postgresql_configuration[%s].value", [var0]), "searchLine": common_lib.build_search_line(["resource", "azurerm_postgresql_configuration", var0, "value"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: PostgreSQL Server Without Connection Throttling"
# description: >-
#   Ensure that Connection Throttling is set for the PostgreSQL server
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.postgre_sql_server_without_connection_throttling"
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
postgre_sql_server_without_connection_throttling_snippet[violation] {
	postgre_sql_server_without_connection_throttling_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
