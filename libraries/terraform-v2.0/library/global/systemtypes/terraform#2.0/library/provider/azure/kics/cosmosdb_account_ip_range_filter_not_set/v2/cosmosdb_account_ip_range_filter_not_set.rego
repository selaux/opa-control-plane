package global.systemtypes["terraform:2.0"].library.provider.azure.kics.cosmosdb_account_ip_range_filter_not_set.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

cosmosdb_account_ip_range_filter_not_set_inner[result] {
	resource := input.document[i].resource.azurerm_cosmosdb_account[name]
	not resource.ip_range_filter
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_cosmosdb_account[%s].ip_range_filter' is undefined", [name]), "keyExpectedValue": sprintf("'azurerm_cosmosdb_account[%s].ip_range_filter' should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_cosmosdb_account", "searchKey": sprintf("azurerm_cosmosdb_account[%s].ip_range_filter", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: CosmosDB Account IP Range Filter Not Set"
# description: >-
#   The IP range filter should be defined to secure the data stored
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.cosmosdb_account_ip_range_filter_not_set"
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
#       identifier: azurerm_cosmosdb_account
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
cosmosdb_account_ip_range_filter_not_set_snippet[violation] {
	cosmosdb_account_ip_range_filter_not_set_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
