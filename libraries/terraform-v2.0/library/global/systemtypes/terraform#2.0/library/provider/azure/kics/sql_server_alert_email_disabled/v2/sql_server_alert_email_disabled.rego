package global.systemtypes["terraform:2.0"].library.provider.azure.kics.sql_server_alert_email_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

sql_server_alert_email_disabled_inner[result] {
	doc := input.document[i]
	resource := doc.resource.azurerm_mssql_server_security_alert_policy[name]
	not common_lib.valid_key(resource, "email_account_admins")
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_mssql_server_security_alert_policy[%s].email_account_admins' is undefined", [name]), "keyExpectedValue": sprintf("'azurerm_mssql_server_security_alert_policy[%s].email_account_admins' should be defined", [name]), "remediation": "email_account_admins = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_mssql_server_security_alert_policy", "searchKey": sprintf("azurerm_mssql_server_security_alert_policy[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_mssql_server_security_alert_policy", name], [])}
}

sql_server_alert_email_disabled_inner[result] {
	doc := input.document[i]
	resource := doc.resource.azurerm_mssql_server_security_alert_policy[name]
	resource.email_account_admins == false
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_mssql_server_security_alert_policy[%s].email_account_admins' is false", [name]), "keyExpectedValue": sprintf("'azurerm_mssql_server_security_alert_policy[%s].email_account_admins' should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_mssql_server_security_alert_policy", "searchKey": sprintf("azurerm_mssql_server_security_alert_policy[%s].email_account_admins", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_mssql_server_security_alert_policy", name, "email_account_admins"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQL Server Alert Email Disabled"
# description: >-
#   SQL Server alert email should be enabled
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.sql_server_alert_email_disabled"
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
#     name: "azurerm"
#     versions:
#       min: "v2"
#       max: "v3"
#   rule_targets:
#     - argument: ""
#       identifier: azurerm_mssql_server_security_alert_policy
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
sql_server_alert_email_disabled_snippet[violation] {
	sql_server_alert_email_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
