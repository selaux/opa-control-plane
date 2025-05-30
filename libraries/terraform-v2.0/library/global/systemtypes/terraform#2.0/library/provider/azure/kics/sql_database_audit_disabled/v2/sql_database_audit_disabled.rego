package global.systemtypes["terraform:2.0"].library.provider.azure.kics.sql_database_audit_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

sql_database_audit_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_sql_database[name]
	not resource.threat_detection_policy
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'threat_detection_policy' is missing", "keyExpectedValue": "'threat_detection_policy' should exist", "remediation": "threat_detection_policy {\n\t\tstate = \"Enabled\"\n\t}\n", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_sql_database", "searchKey": sprintf("azurerm_sql_database[%s].threat_detection_policy", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_sql_database", name, "threat_detection_policy"], [])}
}

sql_database_audit_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_sql_database[name]
	resource.threat_detection_policy.state == "Disabled"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'threat_detection_policy.state' equal 'Disabled'", "keyExpectedValue": "'threat_detection_policy.state' equal 'Enabled'", "remediation": json.marshal({"after": "Enabled", "before": "Disabled"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_sql_database", "searchKey": sprintf("azurerm_sql_database[%s].threat_detection_policy.state", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_sql_database", name, "threat_detection_policy", "state"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SQL Database Audit Disabled"
# description: >-
#   Ensure that 'Threat Detection' is enabled for Azure SQL Database
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.sql_database_audit_disabled"
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
#       identifier: azurerm_sql_database
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
sql_database_audit_disabled_snippet[violation] {
	sql_database_audit_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
