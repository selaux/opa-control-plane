package global.systemtypes["terraform:2.0"].library.provider.azure.kics.function_app_http2_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

function_app_http2_disabled_inner[result] {
	app := input.document[i].resource.azurerm_function_app[name]
	not common_lib.valid_key(app, "site_config")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_function_app[%s].site_config' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_function_app[%s].site_config' should be defined and not null", [name]), "remediation": "site_config {\n\t\thttp2_enabled = true\n\t}\n", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(app, name), "resourceType": "azurerm_function_app", "searchKey": sprintf("azurerm_function_app[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_function_app", name], [])}
}

function_app_http2_disabled_inner[result] {
	app := input.document[i].resource.azurerm_function_app[name]
	not common_lib.valid_key(app.site_config, "http2_enabled")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_function_app[%s].site_config.http2_enabled' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_function_app[%s].site_config.http2_enabled' should be defined and not null", [name]), "remediation": "http2_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(app, name), "resourceType": "azurerm_function_app", "searchKey": sprintf("azurerm_function_app[%s].site_config", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_function_app", name, "site_config"], [])}
}

function_app_http2_disabled_inner[result] {
	app := input.document[i].resource.azurerm_function_app[name]
	app.site_config.http2_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_function_app[%s].site_config.http2_enabled' is set to false", [name]), "keyExpectedValue": sprintf("'azurerm_function_app[%s].site_config.http2_enabled' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(app, name), "resourceType": "azurerm_function_app", "searchKey": sprintf("azurerm_function_app[%s].site_config.http2_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_function_app", name, "site_config", "http2_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Function App HTTP2 Disabled"
# description: >-
#   Function App should have 'http2_enabled' enabled
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.function_app_http2_disabled"
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
function_app_http2_disabled_snippet[violation] {
	function_app_http2_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
