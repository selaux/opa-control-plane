package global.systemtypes["terraform:2.0"].library.provider.azure.kics.function_app_managed_identity_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

function_app_managed_identity_disabled_inner[result] {
	function := input.document[i].resource.azurerm_function_app[name]
	not common_lib.valid_key(function, "identity")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_function_app[%s].identity' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_function_app[%s].identity' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(function, name), "resourceType": "azurerm_function_app", "searchKey": sprintf("azurerm_function_app[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_function_app", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Function App Managed Identity Disabled"
# description: >-
#   Azure Function App should have managed identity enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.function_app_managed_identity_disabled"
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
#       identifier: azurerm_function_app
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
function_app_managed_identity_disabled_snippet[violation] {
	function_app_managed_identity_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
