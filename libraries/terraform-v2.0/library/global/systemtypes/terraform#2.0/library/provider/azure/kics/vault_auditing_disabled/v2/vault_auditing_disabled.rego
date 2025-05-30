package global.systemtypes["terraform:2.0"].library.provider.azure.kics.vault_auditing_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

vault_auditing_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_key_vault[name]
	count({x | diagnosticResource := input.document[x].resource.azurerm_monitor_diagnostic_setting[_]; contains(diagnosticResource.target_resource_id, concat(".", ["azurerm_key_vault", name, "id"]))}) == 0
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'azurerm_key_vault' is not associated with 'azurerm_monitor_diagnostic_setting'", "keyExpectedValue": "'azurerm_key_vault' should be associated with 'azurerm_monitor_diagnostic_setting'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_key_vault", "searchKey": sprintf("azurerm_key_vault[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Vault Auditing Disabled"
# description: >-
#   Ensure that logging for Azure KeyVault is 'Enabled'
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.vault_auditing_disabled"
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
#       identifier: azurerm_key_vault
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
vault_auditing_disabled_snippet[violation] {
	vault_auditing_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
