package global.systemtypes["terraform:2.0"].library.provider.azure.kics.firewall_rule_allows_too_many_hosts_to_access_redis_cache.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

firewall_rule_allows_too_many_hosts_to_access_redis_cache_inner[result] {
	fire_rule := input.document[i].resource.azurerm_redis_firewall_rule[name]
	occupied_hosts := commonLib.calc_IP_value(fire_rule.start_ip)
	all_hosts := commonLib.calc_IP_value(fire_rule.end_ip)
	available := abs(all_hosts - occupied_hosts)
	available > 255
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_redis_firewall_rule[%s].start_ip' and 'end_ip' allow %s hosts", [name, available]), "keyExpectedValue": sprintf("'azurerm_redis_firewall_rule[%s].start_ip' and 'end_ip' should allow no more than 255 hosts", [name]), "resourceName": tf_lib.get_resource_name(fire_rule, name), "resourceType": "azurerm_redis_firewall_rule", "searchKey": sprintf("azurerm_redis_firewall_rule[%s].start_ip", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Firewall Rule Allows Too Many Hosts To Access Redis Cache"
# description: >-
#   Check if any firewall rule allows too many hosts to access Redis Cache
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.firewall_rule_allows_too_many_hosts_to_access_redis_cache"
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
#       identifier: azurerm_redis_firewall_rule
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
firewall_rule_allows_too_many_hosts_to_access_redis_cache_snippet[violation] {
	firewall_rule_allows_too_many_hosts_to_access_redis_cache_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
