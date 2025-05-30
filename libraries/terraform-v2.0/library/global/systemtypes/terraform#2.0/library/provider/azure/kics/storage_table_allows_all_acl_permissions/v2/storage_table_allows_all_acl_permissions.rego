package global.systemtypes["terraform:2.0"].library.provider.azure.kics.storage_table_allows_all_acl_permissions.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

storage_table_allows_all_acl_permissions_inner[result] {
	resource := input.document[i].resource.azurerm_storage_table[name]
	permissions := resource.acl.access_policy.permissions
	p := {"d", "l", "r", "w"}
	count({x | permission := p[x]; contains(permissions, permission)}) == 4
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("azurerm_storage_table[%s].acl.permissions allows all ACL permissions", [name]), "keyExpectedValue": sprintf("azurerm_storage_table[%s].acl.permissions should not allow all ACL permissions", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_storage_table", "searchKey": sprintf("azurerm_storage_table[%s].acl.permissions", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Storage Table Allows All ACL Permissions"
# description: >-
#   Azure Storage Table should not allow all ACL (Access Control List) permissions - r (read), w (write), d (delete), and l (list).
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.storage_table_allows_all_acl_permissions"
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
#       identifier: azurerm_storage_table
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
storage_table_allows_all_acl_permissions_snippet[violation] {
	storage_table_allows_all_acl_permissions_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
