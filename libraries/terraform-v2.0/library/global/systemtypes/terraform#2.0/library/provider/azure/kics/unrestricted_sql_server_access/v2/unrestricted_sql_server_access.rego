package global.systemtypes["terraform:2.0"].library.provider.azure.kics.unrestricted_sql_server_access.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

unrestricted_sql_server_access_inner[result] {
	resource := input.document[i].resource.azurerm_sql_firewall_rule[name]
	startIP_value := common_lib.calc_IP_value(resource.start_ip_address)
	endIP_value := common_lib.calc_IP_value(resource.end_ip_address)
	abs(endIP_value - startIP_value) >= 256
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_sql_firewall_rule[%s].start_ip_address' The difference between the value of the 'end_ip_address' and of 'start_ip_address' is greater than or equal to 256", [name]), "keyExpectedValue": sprintf("'azurerm_sql_firewall_rule[%s].start_ip_address' The difference between the value of the 'end_ip_address' and of 'start_ip_address' should be less than 256", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_sql_firewall_rule", "searchKey": sprintf("azurerm_sql_firewall_rule[%s].start_ip_address", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Unrestricted SQL Server Access"
# description: >-
#   Azure SQL Server Accessibility should be set to a minimal address range to grant the principle of least privileges, which means the difference between the values of the 'end_ip_address' and 'start_ip_address' must be less than 256. Additionally, both ips must be different from '0.0.0.0'.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.unrestricted_sql_server_access"
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
#       identifier: azurerm_sql_firewall_rule
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
unrestricted_sql_server_access_snippet[violation] {
	unrestricted_sql_server_access_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
