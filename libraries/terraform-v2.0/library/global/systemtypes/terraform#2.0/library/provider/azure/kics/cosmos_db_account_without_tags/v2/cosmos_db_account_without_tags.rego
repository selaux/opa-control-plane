package global.systemtypes["terraform:2.0"].library.provider.azure.kics.cosmos_db_account_without_tags.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

cosmos_db_account_without_tags_inner[result] {
	resource := input.document[i].resource.azurerm_cosmosdb_account[name]
	not resource.tags
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("azurerm_cosmosdb_account[%s].tags is undefined'", [name]), "keyExpectedValue": sprintf("azurerm_cosmosdb_account[%s].tags should be defined'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_cosmosdb_account", "searchKey": sprintf("azurerm_cosmosdb_account[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cosmos DB Account Without Tags"
# description: >-
#   Cosmos DB Account must have a mapping of tags.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.cosmos_db_account_without_tags"
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
cosmos_db_account_without_tags_snippet[violation] {
	cosmos_db_account_without_tags_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
