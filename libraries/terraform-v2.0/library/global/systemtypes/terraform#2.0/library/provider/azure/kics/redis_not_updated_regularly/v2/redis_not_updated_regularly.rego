package global.systemtypes["terraform:2.0"].library.provider.azure.kics.redis_not_updated_regularly.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

redis_not_updated_regularly_inner[result] {
	redis_cache := input.document[i].resource.azurerm_redis_cache[name]
	not common_lib.valid_key(redis_cache, "patch_schedule")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_redis_cache[%s].patch_schedule' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_redis_cache[%s].patch_schedule' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(redis_cache, name), "resourceType": "azurerm_redis_cache", "searchKey": sprintf("azurerm_redis_cache[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Redis Not Updated Regularly"
# description: >-
#   Redis Cache is not configured to be updated regularly with security and operational updates
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.redis_not_updated_regularly"
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
redis_not_updated_regularly_snippet[violation] {
	redis_not_updated_regularly_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
