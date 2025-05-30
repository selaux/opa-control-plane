package global.systemtypes["terraform:2.0"].library.provider.azure.kics.mssql_server_auditing_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

mssql_server_auditing_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_mssql_server[name]
	not resource.extended_auditing_policy
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_mssql_server.%s.extended_auditing_policy' does not exist", [name]), "keyExpectedValue": sprintf("'azurerm_mssql_server.%s.extended_auditing_policy' should exist", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_mssql_server", "searchKey": sprintf("azurerm_mssql_server[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: MSSQL Server Auditing Disabled"
# description: >-
#   Make sure that for MSSQL Servers, that 'Auditing' is set to 'On'
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.mssql_server_auditing_disabled"
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
#       identifier: azurerm_mssql_server
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
mssql_server_auditing_disabled_snippet[violation] {
	mssql_server_auditing_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
