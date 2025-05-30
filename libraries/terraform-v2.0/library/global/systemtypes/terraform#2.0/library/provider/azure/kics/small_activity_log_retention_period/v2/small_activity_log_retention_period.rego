package global.systemtypes["terraform:2.0"].library.provider.azure.kics.small_activity_log_retention_period.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

small_activity_log_retention_period_inner[result] {
	monitor := input.document[i].resource.azurerm_monitor_log_profile[name]
	monitor.retention_policy.enabled == true
	not common_lib.valid_key(monitor.retention_policy, "days")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_monitor_log_profile[%s].retention_policy.days' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_monitor_log_profile[%s].retention_policy.days' should be defined and not null", [name]), "remediation": "days = 365", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(monitor, name), "resourceType": "azurerm_monitor_log_profile", "searchKey": sprintf("azurerm_monitor_log_profile[%s].retention_policy", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_monitor_log_profile", name, "retention_policy"], [])}
}

small_activity_log_retention_period_inner[result] {
	monitor := input.document[i].resource.azurerm_monitor_log_profile[name]
	monitor.retention_policy.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_monitor_log_profile[%s].retention_policy.enabled' is set to false", [name]), "keyExpectedValue": sprintf("'azurerm_monitor_log_profile[%s].retention_policy.enabled' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(monitor, name), "resourceType": "azurerm_monitor_log_profile", "searchKey": sprintf("azurerm_monitor_log_profile[%s].retention_policy.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_monitor_log_profile", name, "retention_policy", "enabled"], [])}
}

small_activity_log_retention_period_inner[result] {
	monitor := input.document[i].resource.azurerm_monitor_log_profile[name]
	retentionPolicy := monitor.retention_policy
	retentionPolicy.enabled == true
	common_lib.between(retentionPolicy.days, 1, 364)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_monitor_log_profile[%s].retention_policy.days' is less than 365 days or different than 0 (indefinitely)", [name]), "keyExpectedValue": sprintf("'azurerm_monitor_log_profile[%s].retention_policy.days' should be greater than or equal to 365 days or 0 (indefinitely)", [name]), "remediation": json.marshal({"after": "365", "before": sprintf("%d", [retentionPolicy.days])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(monitor, name), "resourceType": "azurerm_monitor_log_profile", "searchKey": sprintf("azurerm_monitor_log_profile[%s].retention_policy.days", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_monitor_log_profile", name, "retention_policy", "days"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Small Activity Log Retention Period"
# description: >-
#   Ensure that Activity Log Retention is set 365 days or greater
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.small_activity_log_retention_period"
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
#       identifier: azurerm_monitor_log_profile
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
small_activity_log_retention_period_snippet[violation] {
	small_activity_log_retention_period_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
