package global.systemtypes["terraform:2.0"].library.provider.azure.kics.function_app_not_using_latest_tls_encryption_version.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

function_app_not_using_latest_tls_encryption_version_inner[result] {
	app := input.document[i].resource.azurerm_function_app[name]
	app.site_config.min_tls_version != 1.2
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_function_app[%s].site_config.min_tls_version' is not set to '1.2'", [name]), "keyExpectedValue": sprintf("'azurerm_function_app[%s].site_config.min_tls_version' should be set to '1.2'", [name]), "remediation": json.marshal({"after": "1.2", "before": sprintf("%.1f", [app.site_config.min_tls_version])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(app, name), "resourceType": "azurerm_function_app", "searchKey": sprintf("azurerm_function_app[%s].site_config.min_tls_version", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_function_app", name, "site_config", "min_tls_version"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Function App Not Using Latest TLS Encryption Version"
# description: >-
#   Ensure Function App is using the latest version of TLS encryption
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.function_app_not_using_latest_tls_encryption_version"
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
function_app_not_using_latest_tls_encryption_version_snippet[violation] {
	function_app_not_using_latest_tls_encryption_version_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
