package global.systemtypes["terraform:2.0"].library.provider.azure.kics.sql_server_ingress_from_any_ip.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

sql_server_ingress_from_any_ip_inner[result] {
	firewall := input.document[i].resource.azurerm_sql_firewall_rule[name]
	firewall.start_ip_address = "0.0.0.0"
	checkEndIP(firewall.end_ip_address)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "azurerm_sql_firewall_rule.start_ip_address equal to 0.0.0.0 and end_ip_address equal to 0.0.0.0 or 255.255.255.255", "keyExpectedValue": "azurerm_sql_firewall_rule.start_ip_address different from 0.0.0.0 and end_ip_address different from 0.0.0.0 or 255.255.255.255", "resourceName": tf_lib.get_resource_name(firewall, name), "resourceType": "azurerm_sql_firewall_rule", "searchKey": sprintf("azurerm_sql_firewall_rule[%s]", [name])}
}

checkEndIP("255.255.255.255") = true

# METADATA: library-snippet
# version: v1
# title: "KICS: SQLServer Ingress From Any IP"
# description: >-
#   Check if all IPs are allowed, check from start 0.0.0.0 to end 255.255.255.255.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.sql_server_ingress_from_any_ip"
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
sql_server_ingress_from_any_ip_snippet[violation] {
	sql_server_ingress_from_any_ip_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
