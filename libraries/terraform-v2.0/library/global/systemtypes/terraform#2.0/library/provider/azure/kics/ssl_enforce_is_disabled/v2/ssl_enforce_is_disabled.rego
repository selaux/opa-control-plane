package global.systemtypes["terraform:2.0"].library.provider.azure.kics.ssl_enforce_is_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

ssl_enforce_is_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_postgresql_server[var0]
	not common_lib.valid_key(resource, "ssl_enforcement_enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_postgresql_server.%s.ssl_enforcement_enabled' is not defined", [var0]), "keyExpectedValue": sprintf("'azurerm_postgresql_server.%s.ssl_enforcement_enabled' should equal 'true'", [var0]), "remediation": "ssl_enforcement_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, var0), "resourceType": "azurerm_postgresql_server", "searchKey": sprintf("azurerm_postgresql_server[%s].ssl_enforcement_enabled", [var0]), "searchLine": common_lib.build_search_line(["resource", "azurerm_postgresql_server", var0, "ssl_enforcement_enabled"], [])}
}

ssl_enforce_is_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_postgresql_server[var0]
	resource.ssl_enforcement_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_postgresql_server.%s.ssl_enforcement_enabled' is equal 'false'", [var0]), "keyExpectedValue": sprintf("'azurerm_postgresql_server.%s.ssl_enforcement_enabled' should equal 'true'", [var0]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, var0), "resourceType": "azurerm_postgresql_server", "searchKey": sprintf("azurerm_postgresql_server[%s].ssl_enforcement_enabled", [var0]), "searchLine": common_lib.build_search_line(["resource", "azurerm_postgresql_server", var0, "ssl_enforcement_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: SSL Enforce Disabled"
# description: >-
#   Make sure that for PosgreSQL, the 'Enforce SSL connection' is set to 'ENABLED'
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.ssl_enforce_is_disabled"
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
ssl_enforce_is_disabled_snippet[violation] {
	ssl_enforce_is_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
