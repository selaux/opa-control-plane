package global.systemtypes["terraform:2.0"].library.provider.azure.kics.azure_active_directory_authentication.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

azure_active_directory_authentication_inner[result] {
	active := input.document[i].resource.azurerm_service_fabric_cluster[name].azure_active_directory
	not common_lib.valid_key(active, "tenant_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_service_fabric_cluster[%s].azure_active_directory.tenant_id' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_service_fabric_cluster[%s].azure_active_directory.tenant_id' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(active, name), "resourceType": "azurerm_service_fabric_cluster", "searchKey": sprintf("azurerm_service_fabric_cluster[%s].azure_active_directory", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_service_fabric_cluster", name, "azure_active_directory"], [])}
}

azure_active_directory_authentication_inner[result] {
	azure := input.document[i].resource.azurerm_service_fabric_cluster[name]
	not common_lib.valid_key(azure, "azure_active_directory")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_service_fabric_cluster[%s].azure_active_directory' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_service_fabric_cluster[%s].azure_active_directory' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(azure, name), "resourceType": "azurerm_service_fabric_cluster", "searchKey": sprintf("azurerm_service_fabric_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_service_fabric_cluster", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Azure Active Directory Authentication"
# description: >-
#   Azure Active Directory must be used for authentication for Service Fabric
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.azure_active_directory_authentication"
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
#       identifier: azurerm_service_fabric_cluster
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
azure_active_directory_authentication_snippet[violation] {
	azure_active_directory_authentication_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
