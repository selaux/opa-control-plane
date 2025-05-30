package global.systemtypes["terraform:2.0"].library.provider.azure.kics.app_service_without_latest_php_version.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

# for deprecated version (before AzureRM 3.0)
app_service_without_latest_php_version_inner[result] {
	resource := input.document[i].resource.azurerm_app_service[name]
	php_version := resource.site_config.php_version
	to_number(php_version) != 8.1
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'php_version' is not the latest avaliable stable version (8.1)", "keyExpectedValue": "for the attribute 'php_version' should be the latest avaliable stable version (8.1)", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_app_service", "searchKey": sprintf("azurerm_app_service[%s].site_config.php_version", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_app_service", name, "site_config", "php_version"], [])}
}

# After 3.0, for windows
app_service_without_latest_php_version_inner[result] {
	resource := input.document[i].resource.azurerm_windows_web_app[name]
	php_version := resource.site_config.application_stack.php_version
	php_version != "v8.1"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'php_version' is not the latest avaliable stable version (8.1)", "keyExpectedValue": "for the attribute 'php_version' should be the latest avaliable stable version (8.1)", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_windows_web_app", "searchKey": sprintf("azurerm_windows_web_app[%s].site_config.application_stack.php_version", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_windows_web_app", name, "site_config", "application_stack", "php_version"], [])}
}

# After 3.0, for linux
app_service_without_latest_php_version_inner[result] {
	resource := input.document[i].resource.azurerm_linux_web_app[name]
	php_version := resource.site_config.application_stack.php_version
	to_number(php_version) != 8.1
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'php_version' is not the latest avaliable stable version (8.1)", "keyExpectedValue": "for the attribute 'php_version' should be the latest avaliable stable version (8.1)", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_linux_web_app", "searchKey": sprintf("azurerm_linux_web_app[%s].site_config.application_stack.php_version", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_linux_web_app", name, "site_config", "application_stack", "php_version"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: App Service Without Latest PHP Version"
# description: >-
#   Periodically newer versions are released for PHP software either due to security flaws or to include additional functionality. Using the latest PHP version for web apps is recommended in order to take advantage of security fixes, if any, and/or additional functionalities of the newer version.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.app_service_without_latest_php_version"
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
#     - argument: ""
#       identifier: azurerm_linux_web_app
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: azurerm_windows_web_app
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
app_service_without_latest_php_version_snippet[violation] {
	app_service_without_latest_php_version_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
