package global.systemtypes["terraform:2.0"].library.provider.azure.kics.trusted_microsoft_services_not_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

trusted_microsoft_services_not_enabled_inner[result] {
	resource := input.document[i].resource.azurerm_storage_account[name]
	not common_lib.valid_key(resource, "network_rules")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'network_rules' is undefined or null", "keyExpectedValue": "'network_rules' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_storage_account", "searchKey": sprintf("azurerm_storage_account[%s]", [name])}
}

trusted_microsoft_services_not_enabled_inner[result] {
	network_rules := input.document[i].resource.azurerm_storage_account[name].network_rules
	not common_lib.valid_key(network_rules, "bypass")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'network_rules.bypass' is undefined or null", "keyExpectedValue": "'network_rules.bypass' should be defined and not null", "resourceName": tf_lib.get_resource_name(input.document[i].resource.azurerm_storage_account[name], name), "resourceType": "azurerm_storage_account", "searchKey": sprintf("azurerm_storage_account[%s].network_rules", [name])}
}

trusted_microsoft_services_not_enabled_inner[result] {
	resource := input.document[i].resource.azurerm_storage_account[name]
	bypass := resource.network_rules.bypass
	not common_lib.inArray(bypass, "AzureServices")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'network_rules.bypass' does not contain 'AzureServices'", "keyExpectedValue": "'network_rules.bypass' should contain 'AzureServices'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_storage_account", "searchKey": sprintf("azurerm_storage_account[%s].network_rules.bypass", [name])}
}

trusted_microsoft_services_not_enabled_inner[result] {
	resource := input.document[i].resource.azurerm_storage_account_network_rules[name]
	not common_lib.valid_key(resource, "bypass")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'bypass' is undefined or null", "keyExpectedValue": "'bypass' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_storage_account_network_rules", "searchKey": sprintf("azurerm_storage_account_network_rules[%s]", [name])}
}

trusted_microsoft_services_not_enabled_inner[result] {
	network_rules := input.document[i].resource.azurerm_storage_account_network_rules[name]
	bypass := network_rules.bypass
	not common_lib.inArray(bypass, "AzureServices")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'bypass' does not contain 'AzureServices'", "keyExpectedValue": "'bypass' should contain 'AzureServices'", "resourceName": tf_lib.get_resource_name(network_rules, name), "resourceType": "azurerm_storage_account_network_rules", "searchKey": sprintf("azurerm_storage_account_network_rules[%s].bypass", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Trusted Microsoft Services Not Enabled"
# description: >-
#   Trusted Microsoft Services should be enabled for Storage Account access
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.trusted_microsoft_services_not_enabled"
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
#       identifier: azurerm_storage_account
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: azurerm_storage_account_network_rules
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
trusted_microsoft_services_not_enabled_snippet[violation] {
	trusted_microsoft_services_not_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
