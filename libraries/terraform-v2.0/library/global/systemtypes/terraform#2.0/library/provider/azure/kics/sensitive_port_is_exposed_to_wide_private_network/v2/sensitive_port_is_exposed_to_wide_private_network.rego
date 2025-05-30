package global.systemtypes["terraform:2.0"].library.provider.azure.kics.sensitive_port_is_exposed_to_wide_private_network.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

sensitive_port_is_exposed_to_wide_private_network_inner[result] {
	resource := input.document[i].resource.azurerm_network_security_rule[name]
	portContent := commonLib.tcpPortsMap[port]
	portNumber = port
	portName = portContent
	protocol := tf_lib.getProtocolList(resource.protocol)[_]
	upper(resource.access) == "ALLOW"
	upper(resource.direction) == "INBOUND"
	commonLib.isPrivateIP(resource.source_address_prefix)
	tf_lib.containsPort(resource, portNumber)
	isTCPorUDP(protocol)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s (%s:%d) is allowed", [portName, protocol, portNumber]), "keyExpectedValue": sprintf("%s (%s:%d) should not be allowed", [portName, protocol, portNumber]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_network_security_rule", "searchKey": sprintf("azurerm_network_security_rule[%s].destination_port_range", [name])}
}

isTCPorUDP("TCP") = true

isTCPorUDP("UDP") = true

# METADATA: library-snippet
# version: v1
# title: "KICS: Sensitive Port Is Exposed To Wide Private Network"
# description: >-
#   A sensitive port, such as port 23 or port 110, is open for wide private network in either TCP or UDP protocol
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.sensitive_port_is_exposed_to_wide_private_network"
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
#       identifier: azurerm_network_security_rule
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
sensitive_port_is_exposed_to_wide_private_network_snippet[violation] {
	sensitive_port_is_exposed_to_wide_private_network_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
