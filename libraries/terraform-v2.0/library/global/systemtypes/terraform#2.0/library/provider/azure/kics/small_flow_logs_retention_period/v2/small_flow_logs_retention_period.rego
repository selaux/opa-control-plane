package global.systemtypes["terraform:2.0"].library.provider.azure.kics.small_flow_logs_retention_period.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

small_flow_logs_retention_period_inner[result] {
	resource := input.document[i].resource.azurerm_network_watcher_flow_log[name]
	var := resource.retention_policy.days
	var < 90
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'retention_policy.days' is less than 90 [%d])", [var]), "keyExpectedValue": sprintf("'%s.retention_policy.days' should be bigger than 90)", [name]), "remediation": json.marshal({"after": "90", "before": sprintf("%d", [resource.retention_policy.days])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_network_watcher_flow_log", "searchKey": sprintf("azurerm_network_watcher_flow_log[%s].retention_policy.days", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_network_watcher_flow_log", name, "retention_policy", "days"], [])}
}

small_flow_logs_retention_period_inner[result] {
	resource := input.document[i].resource.azurerm_network_watcher_flow_log[name]
	not common_lib.valid_key(resource, "retention_policy")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'%s.retention_policy' doesn't exist)", [name]), "keyExpectedValue": sprintf("'%s.retention_policy' should exist)", [name]), "remediation": "retention_policy {\n\t\tenabled = true\n\t\tdays = 90\n\t}\n", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_network_watcher_flow_log", "searchKey": sprintf("azurerm_network_watcher_flow_log[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_network_watcher_flow_log", name], [])}
}

small_flow_logs_retention_period_inner[result] {
	resource := input.document[i].resource.azurerm_network_watcher_flow_log[name]
	resource.retention_policy
	enabled := resource.retention_policy.enabled
	enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'%s.retention_policy' is disabled)", [name]), "keyExpectedValue": sprintf("'%s.retention_policy' should be enabled)", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_network_watcher_flow_log", "searchKey": sprintf("azurerm_network_watcher_flow_log[%s].retention_policy.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_network_watcher_flow_log", name, "retention_policy", "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Small Flow Logs Retention Period"
# description: >-
#   Flow logs enable capturing information about IP traffic flowing in and out of the network security groups. Network Security Group Flow Logs must be enabled with retention period greater than or equal to 90 days. This is important, because these logs are used to check for anomalies and give information of suspected breaches
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.small_flow_logs_retention_period"
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
#       identifier: azurerm_network_watcher_flow_log
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
small_flow_logs_retention_period_snippet[violation] {
	small_flow_logs_retention_period_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
