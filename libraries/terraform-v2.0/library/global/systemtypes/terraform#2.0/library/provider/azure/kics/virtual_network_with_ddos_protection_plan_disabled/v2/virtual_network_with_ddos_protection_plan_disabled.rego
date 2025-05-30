package global.systemtypes["terraform:2.0"].library.provider.azure.kics.virtual_network_with_ddos_protection_plan_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

virtual_network_with_ddos_protection_plan_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_virtual_network[name]
	not common_lib.valid_key(resource, "ddos_protection_plan")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_virtual_network[%s].ddos_protection_plan' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_virtual_network[%s].ddos_protection_plan' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_virtual_network", "searchKey": sprintf("azurerm_virtual_network[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_virtual_network", name], [])}
}

virtual_network_with_ddos_protection_plan_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_virtual_network[name]
	resource.ddos_protection_plan.enable == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_virtual_network[%s].ddos_protection_plan.enable' is set to false", [name]), "keyExpectedValue": sprintf("'azurerm_virtual_network[%s].ddos_protection_plan.enable' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_virtual_network", "searchKey": sprintf("azurerm_virtual_network[%s].ddos_protection_plan.enable", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_virtual_network", name, "ddos_protection_plan", "enable"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Virtual Network with DDoS Protection Plan disabled"
# description: >-
#   Virtual Network should have DDoS Protection Plan enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.virtual_network_with_ddos_protection_plan_disabled"
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
#       identifier: azurerm_virtual_network
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
virtual_network_with_ddos_protection_plan_disabled_snippet[violation] {
	virtual_network_with_ddos_protection_plan_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
