package global.systemtypes["terraform:2.0"].library.provider.azure.kics.redis_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

redis_publicly_accessible_inner[result] {
	firewall_rule := input.document[i].resource.azurerm_redis_firewall_rule[name]
	not commonLib.isPrivateIP(firewall_rule.start_ip)
	not commonLib.isPrivateIP(firewall_rule.end_ip)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_redis_firewall_rule[%s]' ip range is not private", [name]), "keyExpectedValue": sprintf("'azurerm_redis_firewall_rule[%s]' ip range should be private", [name]), "resourceName": tf_lib.get_resource_name(firewall_rule, name), "resourceType": "azurerm_redis_firewall_rule", "searchKey": sprintf("azurerm_redis_firewall_rule[%s].start_ip", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redis Publicly Accessible"
# description: >-
#   Firewall rule allowing unrestricted access to Redis from other Azure sources
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.redis_publicly_accessible"
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
redis_publicly_accessible_snippet[violation] {
	redis_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
