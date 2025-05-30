package global.systemtypes["terraform:2.0"].library.provider.azure.kics.role_assignment_of_guest_users.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

role_assignment_of_guest_users_inner[result] {
	role_assign := input.document[i].resource.azurerm_role_assignment[name]
	role_assign.role_definition_name == "Guest"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("azurerm_role_assignment[%s].role_definition_name equals to 'Guest'", [name]), "keyExpectedValue": sprintf("azurerm_role_assignment[%s].role_definition_name not equal to 'Guest'", [name]), "resourceName": tf_lib.get_resource_name(role_assign, name), "resourceType": "azurerm_role_assignment", "searchKey": sprintf("azurerm_role_assignment[%s].role_definition_name", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Role Assignment Of Guest Users"
# description: >-
#   There is a role assignment for guest user
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.role_assignment_of_guest_users"
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
role_assignment_of_guest_users_snippet[violation] {
	role_assignment_of_guest_users_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
