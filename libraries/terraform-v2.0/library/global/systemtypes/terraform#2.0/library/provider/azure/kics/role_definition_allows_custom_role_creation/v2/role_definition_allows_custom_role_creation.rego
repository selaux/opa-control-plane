package global.systemtypes["terraform:2.0"].library.provider.azure.kics.role_definition_allows_custom_role_creation.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

role_definition_allows_custom_role_creation_inner[result] {
	resource := input.document[i].resource.azurerm_role_definition[name]
	actions := resource.permissions.actions
	allows_custom_roles_creation(actions)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("azurerm_role_definition[%s].permissions.actions allows custom role creation", [name]), "keyExpectedValue": sprintf("azurerm_role_definition[%s].permissions.actions should not allow custom role creation", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_role_definition", "searchKey": sprintf("azurerm_role_definition[%s].permissions.actions", [name])}
}

customRole := "Microsoft.Authorization/roleDefinitions/write"

allows_custom_roles_creation(actions) {
	count(actions) == 1
	options := {"*", customRole}
	actions[0] == options[x]
} else {
	count(actions) > 1
	actions[x] == customRole
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Role Definition Allows Custom Role Creation"
# description: >-
#   Role Definition should not allow custom role creation (Microsoft.Authorization/roleDefinitions/write)
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.role_definition_allows_custom_role_creation"
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
#       identifier: azurerm_role_definition
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
role_definition_allows_custom_role_creation_snippet[violation] {
	role_definition_allows_custom_role_creation_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
