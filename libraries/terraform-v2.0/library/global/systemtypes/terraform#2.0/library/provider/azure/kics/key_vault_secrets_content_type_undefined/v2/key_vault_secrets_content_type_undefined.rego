package global.systemtypes["terraform:2.0"].library.provider.azure.kics.key_vault_secrets_content_type_undefined.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

key_vault_secrets_content_type_undefined_inner[result] {
	key := input.document[i].resource.azurerm_key_vault_secret[name]
	not common_lib.valid_key(key, "content_type")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_key_vault_secret[%s].content_type' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_key_vault_secret[%s].content_type' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(key, name), "resourceType": "azurerm_key_vault_secret", "searchKey": sprintf("azurerm_key_vault_secret[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_key_vault_secret", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Key Vault Secrets Content Type Undefined"
# description: >-
#   Key Vault Secrets should have set Content Type
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.key_vault_secrets_content_type_undefined"
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
#       identifier: azurerm_key_vault_secret
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
key_vault_secrets_content_type_undefined_snippet[violation] {
	key_vault_secrets_content_type_undefined_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
