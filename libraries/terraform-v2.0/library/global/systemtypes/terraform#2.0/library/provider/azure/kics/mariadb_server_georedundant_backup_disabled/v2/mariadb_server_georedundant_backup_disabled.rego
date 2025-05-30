package global.systemtypes["terraform:2.0"].library.provider.azure.kics.mariadb_server_georedundant_backup_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

mariadb_server_georedundant_backup_disabled_inner[result] {
	mdb := input.document[i].resource.azurerm_mariadb_server[name]
	not common_lib.valid_key(mdb, "geo_redundant_backup_enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_mariadb_server[%s].geo_redundant_backup_enabled' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_mariadb_server[%s].geo_redundant_backup_enabled' should be defined and set to true", [name]), "remediation": "geo_redundant_backup_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(mdb, name), "resourceType": "azurerm_mariadb_server", "searchKey": sprintf("azurerm_mariadb_server[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_mariadb_server", name], [])}
}

mariadb_server_georedundant_backup_disabled_inner[result] {
	mdb := input.document[i].resource.azurerm_mariadb_server[name]
	mdb.geo_redundant_backup_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_mariadb_server[%s].geo_redundant_backup_enabled' is set to false", [name]), "keyExpectedValue": sprintf("'azurerm_mariadb_server[%s].geo_redundant_backup_enabled' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(mdb, name), "resourceType": "azurerm_mariadb_server", "searchKey": sprintf("azurerm_mariadb_server[%s].geo_redundant_backup_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_mariadb_server", name, "geo_redundant_backup_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: MariaDB Server Geo-redundant Backup Disabled"
# description: >-
#   MariaDB Server Geo-redundant Backup should be enabled
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.mariadb_server_georedundant_backup_disabled"
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
#       identifier: azurerm_mariadb_server
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
mariadb_server_georedundant_backup_disabled_snippet[violation] {
	mariadb_server_georedundant_backup_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
