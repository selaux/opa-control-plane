package global.systemtypes["terraform:2.0"].library.provider.azure.kics.mysql_ssl_connection_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

mysql_ssl_connection_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_mysql_server[name]
	resource.ssl_enforcement_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_mysql_server.%s.ssl_enforcement_enabled' is equal 'false'", [name]), "keyExpectedValue": sprintf("'azurerm_mysql_server.%s.ssl_enforcement_enabled' should equal 'true'", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_mssql_server", "searchKey": sprintf("azurerm_mysql_server[%s].ssl_enforcement_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "ssl_enforcement_enabled", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: MySQL SSL Connection Disabled"
# description: >-
#   Make sure that for MySQL Database Server, 'Enforce SSL connection' is enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.mysql_ssl_connection_disabled"
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
#       identifier: ssl_enforcement_enabled
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
mysql_ssl_connection_disabled_snippet[violation] {
	mysql_ssl_connection_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
