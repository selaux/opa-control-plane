package global.systemtypes["terraform:2.0"].library.provider.azure.kics.azure_container_registry_with_no_locks.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

azure_container_registry_with_no_locks_inner[result] {
	resourceRegistry := input.document[i].resource.azurerm_container_registry[name]
	resourceLock := input.document[i].resource.azurerm_management_lock[k]
	scopeSplitted := split(resourceLock.scope, ".")
	not re_match(scopeSplitted[1], name)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_container_registry[%s] scope' does not contain azurerm_management_lock'", [name]), "keyExpectedValue": sprintf("'azurerm_container_registry[%s] scope' should contain azurerm_management_lock'", [name]), "resourceName": tf_lib.get_resource_name(resourceRegistry, name), "resourceType": "azurerm_container_registry", "searchKey": sprintf("azurerm_container_registry[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Azure Container Registry With No Locks"
# description: >-
#   Azurerm Container Registry should contain associated locks, which means 'azurerm_management_lock.scope' should be associated with 'azurerm_container_registry'
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.azure_container_registry_with_no_locks"
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
#       identifier: azurerm_container_registry
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
azure_container_registry_with_no_locks_snippet[violation] {
	azure_container_registry_with_no_locks_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
