package global.systemtypes["terraform:2.0"].library.provider.azure.kics.small_msql_server_audit_retention.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

small_msql_server_audit_retention_inner[result] {
	resource_type := ["azurerm_sql_database", "azurerm_sql_server"]
	resource := input.document[i].resource[resource_type[t]][name]
	not common_lib.valid_key(resource.extended_auditing_policy, "retention_in_days")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "extended_auditing_policy.retention_in_days is not defined", "keyExpectedValue": "extended_auditing_policy.retention_in_days should be defined and bigger than 90", "remediation": "retention_in_days = 200", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resource_type[t], "searchKey": sprintf("%s[%s].extended_auditing_policy", [resource_type[t], name]), "searchLine": common_lib.build_search_line(["resource", resource_type[t], name, "extended_auditing_policy"], [])}
}

small_msql_server_audit_retention_inner[result] {
	resource_type := ["azurerm_sql_database", "azurerm_sql_server"]
	resource := input.document[i].resource[resource_type[t]][name]
	var := resource.extended_auditing_policy.retention_in_days
	var <= 90
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'extended_auditing_policy.retention_in_days' is %d", [var]), "keyExpectedValue": sprintf("'%s.extended_auditing_policy.retention_in_days' should be bigger than 90", [name]), "remediation": json.marshal({"after": "200", "before": sprintf("%d", [var])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resource_type[t], "searchKey": sprintf("%s[%s].extended_auditing_policy.retention_in_days", [resource_type[t], name]), "searchLine": common_lib.build_search_line(["resource", resource_type[t], name, "extended_auditing_policy", "retention_in_days"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Small MSSQL Server Audit Retention"
# description: >-
#   Make sure for SQL Servers that Auditing Retention is greater than 90 days
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.small_msql_server_audit_retention"
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
#       identifier: azurerm_sql_database
#       name: ""
#       scope: resource
#       service: ""
#     - argument: ""
#       identifier: azurerm_sql_server
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
small_msql_server_audit_retention_snippet[violation] {
	small_msql_server_audit_retention_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
