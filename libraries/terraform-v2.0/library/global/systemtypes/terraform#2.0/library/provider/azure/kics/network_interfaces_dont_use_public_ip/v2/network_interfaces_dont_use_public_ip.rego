package global.systemtypes["terraform:2.0"].library.provider.azure.kics.network_interfaces_dont_use_public_ip.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

network_interfaces_dont_use_public_ip_inner[result] {
	network := input.document[i].resource.azurerm_network_interface[name].ip_configuration
	common_lib.valid_key(network, "public_ip_address_id")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_network_interface[%s].ip_configuration.public_ip_address_id' is defined", [name]), "keyExpectedValue": sprintf("'azurerm_network_interface[%s].ip_configuration.public_ip_address_id' should be undefined", [name]), "resourceName": tf_lib.get_resource_name(input.document[i].resource.azurerm_network_interface[name], name), "resourceType": "azurerm_network_interface", "searchKey": sprintf("azurerm_network_interface[%s].ip_configuration.public_ip_address_id", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_network_interface", name, "ip_configuration", "public_ip_address_id"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Network Interfaces With Public IP"
# description: >-
#   Network Interfaces should not be exposed with a public IP address. If configured, additional security baselines should be followed (https://docs.microsoft.com/en-us/security/benchmark/azure/baselines/virtual-network-security-baseline, https://docs.microsoft.com/en-us/security/benchmark/azure/baselines/public-ip-security-baseline)
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.network_interfaces_dont_use_public_ip"
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
#       identifier: azurerm_network_interface
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
network_interfaces_dont_use_public_ip_snippet[violation] {
	network_interfaces_dont_use_public_ip_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
