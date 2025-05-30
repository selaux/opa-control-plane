package global.systemtypes["terraform:2.0"].library.provider.azure.kics.default_azure_storage_account_network_access_is_too_permissive.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

default_azure_storage_account_network_access_is_too_permissive_inner[result] {
	networkRules := input.document[i].resource.azurerm_storage_account[name].network_rules
	networkRules.default_action == "Allow"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'default_action' is set to 'Allow'", "keyExpectedValue": "Expected 'default_action' should be set to 'Deny'", "remediation": json.marshal({"after": "Deny", "before": "Allow"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(input.document[i].resource.azurerm_storage_account[name], name), "resourceType": "azurerm_storage_account", "searchKey": sprintf("azurerm_storage_account[%s].network_rules.default_action", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_storage_account", name, "network_rules", "default_action"], [])}
}

default_azure_storage_account_network_access_is_too_permissive_inner[result] {
	networkRules := input.document[i].resource.azurerm_storage_account_network_rules[name]
	networkRules.default_action == "Allow"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'default_action' is set to 'Allow'", "keyExpectedValue": "Expected 'default_action' should be set to 'Deny'", "remediation": json.marshal({"after": "Deny", "before": "Allow"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(networkRules, name), "resourceType": "azurerm_storage_account_network_rules", "searchKey": sprintf("azurerm_storage_account_network_rules[%s].default_action", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_storage_account_network_rules", name, "default_action"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Default Azure Storage Account Network Access Is Too Permissive"
# description: >-
#   Default Azure Storage Account network access should be set to Deny
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.default_azure_storage_account_network_access_is_too_permissive"
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
default_azure_storage_account_network_access_is_too_permissive_snippet[violation] {
	default_azure_storage_account_network_access_is_too_permissive_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
