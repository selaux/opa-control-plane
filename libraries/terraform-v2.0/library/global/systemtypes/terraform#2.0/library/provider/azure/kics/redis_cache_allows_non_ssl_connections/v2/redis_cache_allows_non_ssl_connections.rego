package global.systemtypes["terraform:2.0"].library.provider.azure.kics.redis_cache_allows_non_ssl_connections.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

redis_cache_allows_non_ssl_connections_inner[result] {
	cache := input.document[i].resource.azurerm_redis_cache[name]
	cache.enable_non_ssl_port == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_redis_cache[%s].enable_non_ssl_port' is true", [name]), "keyExpectedValue": sprintf("'azurerm_redis_cache[%s].enable_non_ssl_port' should be set to false or undefined (false as default)", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cache, name), "resourceType": "azurerm_redis_cache", "searchKey": sprintf("azurerm_redis_cache[%s].enable_non_ssl_port", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_redis_cache", name, "enable_non_ssl_port"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redis Cache Allows Non SSL Connections"
# description: >-
#   Redis Cache resources should not allow non-SSL connections
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.redis_cache_allows_non_ssl_connections"
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
#       identifier: azurerm_redis_cache
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
redis_cache_allows_non_ssl_connections_snippet[violation] {
	redis_cache_allows_non_ssl_connections_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
