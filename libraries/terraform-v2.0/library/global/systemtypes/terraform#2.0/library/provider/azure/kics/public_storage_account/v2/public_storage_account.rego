package global.systemtypes["terraform:2.0"].library.provider.azure.kics.public_storage_account.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

public_storage_account_inner[result] {
	network_rules := input.document[i].resource.azurerm_storage_account[name].network_rules
	network_rules.ip_rules[l] == "0.0.0.0/0"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'network_rules.ip_rules' contains 0.0.0.0/0", "keyExpectedValue": "'network_rules.ip_rules' should not contain 0.0.0.0/0", "resourceName": tf_lib.get_resource_name(input.document[i].resource.azurerm_storage_account[name], name), "resourceType": "azurerm_storage_account", "searchKey": sprintf("azurerm_storage_account[%s].network_rules.ip_rules", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_storage_account", name, "network_rules", "ip_rules"], [l])}
}

public_storage_account_inner[result] {
	network_rules := input.document[i].resource.azurerm_storage_account[name].network_rules
	not common_lib.valid_key(network_rules, "ip_rules")
	network_rules.default_action == "Allow"
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'network_rules.default_action' is 'Allow' and 'network_rules.ip_rules' is undefined or null", "keyExpectedValue": "'network_rules.ip_rules' should be defined and not null", "resourceName": tf_lib.get_resource_name(input.document[i].resource.azurerm_storage_account[name], name), "resourceType": "azurerm_storage_account", "searchKey": sprintf("azurerm_storage_account[%s].network_rules", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_storage_account", name, "network_rules"], [])}
}

public_storage_account_inner[result] {
	rules := input.document[i].resource.azurerm_storage_account_network_rules[name]
	rules.ip_rules[l] == "0.0.0.0/0"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("ip_rules[%d] contains 0.0.0.0/0", [l]), "keyExpectedValue": sprintf("ip_rules[%d] should not contain 0.0.0.0/0", [l]), "resourceName": tf_lib.get_resource_name(rules, name), "resourceType": "azurerm_storage_account_network_rules", "searchKey": sprintf("azurerm_storage_account_network_rules[%s].ip_rules", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_storage_account_network_rules", name, "ip_rules"], [l])}
}

public_storage_account_inner[result] {
	rules := input.document[i].resource.azurerm_storage_account_network_rules[name]
	not common_lib.valid_key(rules, "ip_rules")
	rules.default_action == "Allow"
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'default_action' is set to 'Allow' and 'ip_rules' is undefined or null", "keyExpectedValue": "'ip_rules' should be defined and not null", "resourceName": tf_lib.get_resource_name(rules, name), "resourceType": "azurerm_storage_account_network_rules", "searchKey": sprintf("azurerm_storage_account_network_rules[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_storage_account_network_rules", name], [])}
}

public_storage_account_inner[result] {
	storage := input.document[i].resource.azurerm_storage_account[name]
	storage.allow_blob_public_access != false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'allow_blob_public_access' is set to true", "keyExpectedValue": "'allow_blob_public_access' should be set to false or undefined", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(storage, name), "resourceType": "azurerm_storage_account", "searchKey": sprintf("azurerm_storage_account[%s].allow_blob_public_access", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_storage_account", name, "allow_blob_public_access"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Public Storage Account"
# description: >-
#   Storage Account should not be public to grant the principle of least privileges
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.public_storage_account"
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
public_storage_account_snippet[violation] {
	public_storage_account_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
