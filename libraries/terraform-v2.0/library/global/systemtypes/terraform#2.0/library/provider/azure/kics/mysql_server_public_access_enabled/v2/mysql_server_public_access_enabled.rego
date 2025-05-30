package global.systemtypes["terraform:2.0"].library.provider.azure.kics.mysql_server_public_access_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

mysql_server_public_access_enabled_inner[result] {
	doc := input.document[i]
	resource := doc.resource.azurerm_mysql_server[name]
	not common_lib.valid_key(resource, "public_network_access_enabled")
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_mysql_server[%s].public_network_access_enabled' is undefined", [name]), "keyExpectedValue": sprintf("'azurerm_mysql_server[%s].public_network_access_enabled' should be defined", [name]), "remediation": "public_network_access_enabled = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_mssql_server", "searchKey": sprintf("azurerm_mysql_server[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_mysql_server", name], [])}
}

mysql_server_public_access_enabled_inner[result] {
	doc := input.document[i]
	resource := doc.resource.azurerm_mysql_server[name]
	resource.public_network_access_enabled == true
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_mysql_server[%s].public_network_access_enabled' is set to true", [name]), "keyExpectedValue": sprintf("'azurerm_mysql_server[%s].public_network_access_enabled' should be set to false", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_mssql_server", "searchKey": sprintf("azurerm_mysql_server[%s].public_network_access_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_mysql_server", name, "public_network_access_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: MySQL Server Public Access Enabled"
# description: >-
#   MySQL Server public access should be disabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.mysql_server_public_access_enabled"
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
#       identifier: azurerm_mysql_server
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
mysql_server_public_access_enabled_snippet[violation] {
	mysql_server_public_access_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
