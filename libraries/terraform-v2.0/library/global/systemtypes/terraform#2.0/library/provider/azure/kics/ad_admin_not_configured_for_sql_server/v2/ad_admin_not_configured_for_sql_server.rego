package global.systemtypes["terraform:2.0"].library.provider.azure.kics.ad_admin_not_configured_for_sql_server.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

ad_admin_not_configured_for_sql_server_inner[result] {
	sql_server := input.document[i].resource.azurerm_sql_server[name]
	not adAdminExists(sql_server.name, sql_server.resource_group_name, name)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("A 'azurerm_sql_active_directory_administrator' is not defined for 'azurerm_sql_server[%s]'", [name]), "keyExpectedValue": sprintf("A 'azurerm_sql_active_directory_administrator' should be defined for 'azurerm_sql_server[%s]'", [name]), "resourceName": tf_lib.get_resource_name(sql_server, name), "resourceType": "azurerm_sql_server", "searchKey": sprintf("azurerm_sql_server[%s]", [name])}
}

adAdminExists(server_name, resource_group, n) {
	ad_admin := input.document[i].resource.azurerm_sql_active_directory_administrator[name]
	ad_admin.server_name == server_name
} else {
	ad_admin := input.document[i].resource.azurerm_sql_active_directory_administrator[name]
	ad_admin.server_name == sprintf("${azurerm_sql_server.%s.name}", [n])
} else = false

# METADATA: library-snippet
# version: v1
# title: "KICS: AD Admin Not Configured For SQL Server"
# description: >-
#   The Active Directory Administrator is not configured for a SQL server
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.ad_admin_not_configured_for_sql_server"
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
#     name: "azurerm"
#     versions:
#       min: "v2"
#       max: "v3"
#   rule_targets:
#     - argument: ""
#       identifier: azurerm_sql_server
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
ad_admin_not_configured_for_sql_server_snippet[violation] {
	ad_admin_not_configured_for_sql_server_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
