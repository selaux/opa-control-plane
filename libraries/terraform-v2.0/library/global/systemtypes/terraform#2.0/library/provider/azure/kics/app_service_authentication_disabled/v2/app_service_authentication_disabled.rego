package global.systemtypes["terraform:2.0"].library.provider.azure.kics.app_service_authentication_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

app_service_authentication_disabled_inner[result] {
	doc := input.document[i]
	resource := doc.resource.azurerm_app_service[name]
	not common_lib.valid_key(resource, "auth_settings")
	result := {"documentId": doc.id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_app_service[%s].auth_settings' is undefined", [name]), "keyExpectedValue": sprintf("'azurerm_app_service[%s].auth_settings' should be defined", [name]), "remediation": "auth_settings {\n\t\tenabled = true\n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_app_service", "searchKey": sprintf("azurerm_app_service[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_app_service", name], [])}
}

app_service_authentication_disabled_inner[result] {
	doc := input.document[i]
	resource := doc.resource.azurerm_app_service[name]
	resource.auth_settings.enabled == false
	result := {"documentId": doc.id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_app_service[%s].auth_settings.enabled' is false", [name]), "keyExpectedValue": sprintf("'azurerm_app_service[%s].auth_settings.enabled' should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_app_service", "searchKey": sprintf("azurerm_app_service[%s].auth_settings.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_app_service", name, "auth_settings", "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: App Service Authentication Disabled"
# description: >-
#   Azure App Service authentication settings should be enabled
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.app_service_authentication_disabled"
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
#       identifier: azurerm_app_service
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
app_service_authentication_disabled_snippet[violation] {
	app_service_authentication_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
