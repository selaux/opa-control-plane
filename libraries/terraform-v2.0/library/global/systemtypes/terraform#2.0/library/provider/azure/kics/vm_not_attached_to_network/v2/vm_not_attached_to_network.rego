package global.systemtypes["terraform:2.0"].library.provider.azure.kics.vm_not_attached_to_network.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

vm_not_attached_to_network_inner[result] {
	vm := input.document[i].resource.azurerm_virtual_machine[name]
	count(vm.network_interface_ids) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_virtual_machine[%s].network_interface_ids' list is empty", [name]), "keyExpectedValue": sprintf("'azurerm_virtual_machine[%s].network_interface_ids' list should not be empty", [name]), "resourceName": tf_lib.get_resource_name(vm, name), "resourceType": "azurerm_virtual_machine", "searchKey": sprintf("azurerm_virtual_machine[%s].network_interface_ids", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: VM Not Attached To Network"
# description: >-
#   No Network Security Group is attached to the Virtual Machine
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.vm_not_attached_to_network"
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
#       identifier: azurerm_virtual_machine
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
vm_not_attached_to_network_snippet[violation] {
	vm_not_attached_to_network_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
