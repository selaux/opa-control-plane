package global.systemtypes["terraform:2.0"].library.provider.azure.kics.function_app_ftps_enforce_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

function_app_ftps_enforce_disabled_inner[result] {
	function := input.document[i].resource.azurerm_function_app[name]
	not common_lib.valid_key(function.site_config, "ftps_state")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_function_app[%s].site_config.ftps_state' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_function_app[%s].site_config.ftps_state' should be defined and not null", [name]), "remediation": "ftps_state = \"FtpsOnly\"", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(function, name), "resourceType": "azurerm_function_app", "searchKey": sprintf("azurerm_function_app[%s].site_config'", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_function_app", name, "site_config"], [])}
}

function_app_ftps_enforce_disabled_inner[result] {
	function := input.document[i].resource.azurerm_function_app[name]
	function.site_config.ftps_state == "AllAllowed"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_function_app[%s].site_config.ftps_state' is set to 'AllAllowed'", [name]), "keyExpectedValue": sprintf("'azurerm_function_app[%s].site_config.ftps_state' should not be set to 'AllAllowed'", [name]), "remediation": json.marshal({"after": "FtpsOnly", "before": "AllAllowed"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(function, name), "resourceType": "azurerm_function_app", "searchKey": sprintf("azurerm_function_app[%s].site_config.ftps_state", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_function_app", name, "site_config", "ftps_state"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Function App FTPS Enforce Disabled"
# description: >-
#   Azure Function App should only enforce FTPS when 'ftps_state' is enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.function_app_ftps_enforce_disabled"
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
function_app_ftps_enforce_disabled_snippet[violation] {
	function_app_ftps_enforce_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
