package global.systemtypes["terraform:2.0"].library.provider.azure.kics.azure_front_door_waf_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

azure_front_door_waf_disabled_inner[result] {
	door := input.document[i].resource.azurerm_frontdoor[name].frontend_endpoint
	not common_lib.valid_key(door, "web_application_firewall_policy_link_id")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_frontdoor[%s].frontend_endpoint.web_application_firewall_policy_link_id' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_frontdoor[%s].frontend_endpoint.web_application_firewall_policy_link_id' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(door, name), "resourceType": "azurerm_frontdoor", "searchKey": sprintf("azurerm_frontdoor[%s].frontend_endpoint", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_frontdoor", name, "frontend_endpoint"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Azure Front Door WAF Disabled"
# description: >-
#   Azure Front Door WAF should be enabled
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.azure_front_door_waf_disabled"
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
#       identifier: azurerm_frontdoor
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
azure_front_door_waf_disabled_snippet[violation] {
	azure_front_door_waf_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
