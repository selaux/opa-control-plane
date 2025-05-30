package global.systemtypes["terraform:2.0"].library.provider.azure.kics.admin_user_enabled_for_container_registry.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

admin_user_enabled_for_container_registry_inner[result] {
	resource := input.document[i].resource.azurerm_container_registry[name]
	resource.admin_enabled == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'admin_enabled' equal 'true'", "keyExpectedValue": "'admin_enabled' equal 'false'", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_container_registry", "searchKey": sprintf("azurerm_container_registry[%s].admin_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_container_registry", name, "admin_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Admin User Enabled For Container Registry"
# description: >-
#   Admin user is enabled for Container Registry
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.admin_user_enabled_for_container_registry"
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
#       identifier: azurerm_container_registry
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
admin_user_enabled_for_container_registry_snippet[violation] {
	admin_user_enabled_for_container_registry_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
