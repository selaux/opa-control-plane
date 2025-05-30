package global.systemtypes["terraform:2.0"].library.provider.azure.kics.postgresql_server_threat_detection_policy_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

postgresql_server_threat_detection_policy_disabled_inner[result] {
	pg := input.document[i].resource.azurerm_postgresql_server[name]
	not common_lib.valid_key(pg, "threat_detection_policy")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_postgresql_server[%s].threat_detection_policy' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_postgresql_server[%s].threat_detection_policy' is a defined object", [name]), "remediation": "threat_detection_policy = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(pg, name), "resourceType": "azurerm_postgresql_server", "searchKey": sprintf("azurerm_postgresql_server[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_postgresql_server", name], [])}
}

postgresql_server_threat_detection_policy_disabled_inner[result] {
	pg := input.document[i].resource.azurerm_postgresql_server[name]
	pg.threat_detection_policy.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_postgresql_server[%s].threat_detection_policy.enabled' is set to false", [name]), "keyExpectedValue": sprintf("'azurerm_postgresql_server[%s].threat_detection_policy.enabled' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(pg, name), "resourceType": "azurerm_postgresql_server", "searchKey": sprintf("azurerm_postgresql_server[%s].threat_detection_policy.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_postgresql_server", name, "threat_detection_policy", "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: PostgreSQL Server Threat Detection Policy Disabled"
# description: >-
#   PostgreSQL Server Threat Detection Policy should be enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.postgresql_server_threat_detection_policy_disabled"
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
#       identifier: azurerm_postgresql_server
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
postgresql_server_threat_detection_policy_disabled_snippet[violation] {
	postgresql_server_threat_detection_policy_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
