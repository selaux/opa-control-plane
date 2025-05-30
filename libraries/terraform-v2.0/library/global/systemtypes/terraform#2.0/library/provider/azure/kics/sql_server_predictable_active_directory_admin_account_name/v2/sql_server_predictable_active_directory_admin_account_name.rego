package global.systemtypes["terraform:2.0"].library.provider.azure.kics.sql_server_predictable_active_directory_admin_account_name.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

sql_server_predictable_active_directory_admin_account_name_inner[result] {
	resource := input.document[i].resource.azurerm_sql_active_directory_administrator[name]
	count(resource.login) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_sql_active_directory_administrator[%s].login' is empty", [name]), "keyExpectedValue": sprintf("'azurerm_sql_active_directory_administrator[%s].login' should not be empty'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_sql_active_directory_administrator", "searchKey": sprintf("azurerm_sql_active_directory_administrator[%s].login", [name])}
}

sql_server_predictable_active_directory_admin_account_name_inner[result] {
	resource := input.document[i].resource.azurerm_sql_active_directory_administrator[name]
	check_predictable(resource.login)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_sql_active_directory_administrator[%s].login' is predictable", [name]), "keyExpectedValue": sprintf("'azurerm_sql_active_directory_administrator[%s].login' should not be predictable'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_sql_active_directory_administrator", "searchKey": sprintf("azurerm_sql_active_directory_administrator[%s].login", [name])}
}

check_predictable(x) {
	predictable_names := {"admin", "administrator", "sqladmin", "root", "user", "azure_admin", "azure_administrator", "guest"}
	some i
	predictable_names[i] == lower(x)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQL Server Predictable Active Directory Account Name"
# description: >-
#   Azure SQL Server must avoid using predictable Active Directory Administrator Account names, like 'Admin', which means the attribute 'login' must be set to a name that is not easy to predict
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.sql_server_predictable_active_directory_admin_account_name"
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
#       identifier: azurerm_sql_active_directory_administrator
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
sql_server_predictable_active_directory_admin_account_name_snippet[violation] {
	sql_server_predictable_active_directory_admin_account_name_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
