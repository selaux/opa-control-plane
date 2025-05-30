package global.systemtypes["terraform:2.0"].library.provider.azure.kics.waf_is_disabled_for_azure_application_gateway.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

waf_is_disabled_for_azure_application_gateway_inner[result] {
	gateway := input.document[i].resource.azurerm_application_gateway[name]
	not common_lib.valid_key(gateway, "waf_configuration")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_application_gateway[%s]' is undefined", [name]), "keyExpectedValue": sprintf("'azurerm_application_gateway[%s]' should be set", [name]), "resourceName": tf_lib.get_resource_name(gateway, name), "resourceType": "azurerm_application_gateway", "searchKey": sprintf("azurerm_application_gateway[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_application_gateway", name], [])}
}

waf_is_disabled_for_azure_application_gateway_inner[result] {
	gateway := input.document[i].resource.azurerm_application_gateway[name]
	waf := gateway.waf_configuration
	waf.enabled != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_application_gateway[%s].waf_configuration.enabled' is false", [name]), "keyExpectedValue": sprintf("'azurerm_application_gateway[%s].waf_configuration.enabled' is true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(gateway, name), "resourceType": "azurerm_application_gateway", "searchKey": sprintf("azurerm_application_gateway[%s].waf_configuration.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_application_gateway", name, "waf_configuration", "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: WAF Is Disabled For Azure Application Gateway"
# description: >-
#   Check if Web Application Firewall is disabled or not configured for Azure's Application Gateway.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.waf_is_disabled_for_azure_application_gateway"
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
#       identifier: azurerm_application_gateway
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
waf_is_disabled_for_azure_application_gateway_snippet[violation] {
	waf_is_disabled_for_azure_application_gateway_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
