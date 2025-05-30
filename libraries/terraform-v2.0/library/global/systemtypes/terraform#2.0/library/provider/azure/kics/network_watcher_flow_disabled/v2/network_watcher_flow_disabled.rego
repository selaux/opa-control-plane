package global.systemtypes["terraform:2.0"].library.provider.azure.kics.network_watcher_flow_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

network_watcher_flow_disabled_inner[result] {
	network := input.document[i].resource.azurerm_network_watcher_flow_log[name]
	network.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "azurerm_network_watcher_flow_log.enabled is false", "keyExpectedValue": "azurerm_network_watcher_flow_log.enabled should be true", "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(network, name), "resourceType": "azurerm_network_watcher_flow_log", "searchKey": sprintf("azurerm_network_watcher_flow_log[%s].enable", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_network_watcher_flow_log", name, "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Network Watcher Flow Disabled"
# description: >-
#   Check if enable field in the resource azurerm_network_watcher_flow_log is false.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.network_watcher_flow_disabled"
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
#       identifier: azurerm_network_watcher_flow_log
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
network_watcher_flow_disabled_snippet[violation] {
	network_watcher_flow_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
