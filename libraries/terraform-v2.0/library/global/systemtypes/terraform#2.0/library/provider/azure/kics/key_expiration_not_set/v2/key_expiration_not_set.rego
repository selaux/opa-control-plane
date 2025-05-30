package global.systemtypes["terraform:2.0"].library.provider.azure.kics.key_expiration_not_set.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

key_expiration_not_set_inner[result] {
	resource := input.document[i].resource.azurerm_key_vault_key[name]
	not resource.expiration_date
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'expiration_date' is missing", "keyExpectedValue": "'expiration_date' should exist", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_key_vault_key", "searchKey": sprintf("azurerm_key_vault_key[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Key Expiration Not Set"
# description: >-
#   Make sure that for all keys the expiration date is set
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.key_expiration_not_set"
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
#       identifier: azurerm_key_vault_key
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
key_expiration_not_set_snippet[violation] {
	key_expiration_not_set_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
