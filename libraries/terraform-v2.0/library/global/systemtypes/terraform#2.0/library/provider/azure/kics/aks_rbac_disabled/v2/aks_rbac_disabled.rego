package global.systemtypes["terraform:2.0"].library.provider.azure.kics.aks_rbac_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

aks_rbac_disabled_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	rbac := cluster.role_based_access_control
	rbac.enabled != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].role_based_access_control.enabled' is not set to true", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].role_based_access_control.enabled' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s].role_based_access_control.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name, "role_based_access_control", "enabled"], [])}
	# before azurerm 3.0

}

aks_rbac_disabled_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	cluster.role_based_access_control_enabled != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].role_based_access_control_enabled' is not set to true", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].role_based_access_control_enabled' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s].role_based_access_control_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name, "role_based_access_control_enabled"], [])}
	# after azurerm 3.0

}

# METADATA: library-snippet
# version: v1
# title: "KICS: AKS RBAC Disabled"
# description: >-
#   Azure Container Service (AKS) instance should have role-based access control (RBAC) enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.aks_rbac_disabled"
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
#       identifier: azurerm_kubernetes_cluster
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
aks_rbac_disabled_snippet[violation] {
	aks_rbac_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
