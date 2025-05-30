package global.systemtypes["terraform:2.0"].library.provider.azure.kics.role_assignment_not_limit_guest_users_permissions.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

role_assignment_not_limit_guest_users_permissions_inner[result] {
	role_assign := input.document[i].resource.azurerm_role_assignment[name]
	role_assign.role_definition_name == "Guest"
	ref := split(role_assign.role_definition_id, ".")
	role_definition := input.document[_].resource.azurerm_role_definition[ref[1]]
	not restricted(role_definition)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("azurerm_role_assignment[%s].role_definition_id does not limit guest user permissions", [name]), "keyExpectedValue": sprintf("azurerm_role_assignment[%s].role_definition_id limits guest user permissions", [name]), "resourceName": tf_lib.get_resource_name(role_assign, name), "resourceType": "azurerm_role_assignment", "searchKey": sprintf("azurerm_role_assignment[%s].role_definition_id", [name])}
}

restricted(resource) {
	count(resource.permissions.not_actions) != 0
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Role Assignment Not Limit Guest User Permissions"
# description: >-
#   Role Assignment should limit guest user permissions
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.role_assignment_not_limit_guest_users_permissions"
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
#       identifier: azurerm_role_assignment
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
role_assignment_not_limit_guest_users_permissions_snippet[violation] {
	role_assignment_not_limit_guest_users_permissions_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
