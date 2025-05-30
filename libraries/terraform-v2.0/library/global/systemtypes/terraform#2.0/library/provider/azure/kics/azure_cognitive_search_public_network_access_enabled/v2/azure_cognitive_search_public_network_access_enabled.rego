package global.systemtypes["terraform:2.0"].library.provider.azure.kics.azure_cognitive_search_public_network_access_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

azure_cognitive_search_public_network_access_enabled_inner[result] {
	search := input.document[i].resource.azurerm_search_service[name]
	not common_lib.valid_key(search, "public_network_access_enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_search_service[%s].public_network_access_enabled' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_search_service[%s].public_network_access_enabled' should be defined and set to false", [name]), "remediation": "public_network_access_enabled = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(search, name), "resourceType": "azurerm_search_service", "searchKey": sprintf("azurerm_search_service[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_search_service", name], [])}
}

azure_cognitive_search_public_network_access_enabled_inner[result] {
	search := input.document[i].resource.azurerm_search_service[name]
	search.public_network_access_enabled == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_search_service[%s].public_network_access_enabled' is set to true", [name]), "keyExpectedValue": sprintf("'azurerm_search_service[%s].public_network_access_enabled' should be set to false", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(search, name), "resourceType": "azurerm_search_service", "searchKey": sprintf("azurerm_search_service[%s].public_network_access_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_search_service", name, "public_network_access_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Azure Cognitive Search Public Network Access Enabled"
# description: >-
#   Public Network Access should be disabled for Azure Cognitive Search
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.azure_cognitive_search_public_network_access_enabled"
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
#       identifier: azurerm_search_service
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
azure_cognitive_search_public_network_access_enabled_snippet[violation] {
	azure_cognitive_search_public_network_access_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
