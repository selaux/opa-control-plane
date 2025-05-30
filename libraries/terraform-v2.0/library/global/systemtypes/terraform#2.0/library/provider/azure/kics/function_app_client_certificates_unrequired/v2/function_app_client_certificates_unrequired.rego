package global.systemtypes["terraform:2.0"].library.provider.azure.kics.function_app_client_certificates_unrequired.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

function_app_client_certificates_unrequired_inner[result] {
	function := input.document[i].resource.azurerm_function_app[name]
	not common_lib.valid_key(function, "client_cert_mode")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_function_app[%s].client_cert_mode' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_function_app[%s].client_cert_mode' should be defined and not null", [name]), "remediation": "client_cert_mode = \"Required\"", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(function, name), "resourceType": "azurerm_function_app", "searchKey": sprintf("azurerm_function_app[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_function_app", name], [])}
}

function_app_client_certificates_unrequired_inner[result] {
	function := input.document[i].resource.azurerm_function_app[name]
	function.client_cert_mode != "Required"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_function_app[%s].client_cert_mode' is not set to 'Required'", [name]), "keyExpectedValue": sprintf("'azurerm_function_app[%s].client_cert_mode' should be set to 'Required'", [name]), "remediation": json.marshal({"after": "Required", "before": sprintf("%s", [function.client_cert_mode])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(function, name), "resourceType": "azurerm_function_app", "searchKey": sprintf("azurerm_function_app[%s].client_cert_mode", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_function_app", name, "client_cert_mode"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Function App Client Certificates Unrequired"
# description: >-
#   Azure Function App should have 'client_cert_mode' set to required
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.function_app_client_certificates_unrequired"
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
function_app_client_certificates_unrequired_snippet[violation] {
	function_app_client_certificates_unrequired_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
