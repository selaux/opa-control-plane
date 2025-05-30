package global.systemtypes["terraform:2.0"].library.provider.azure.kics.aks_uses_azure_policies_addon_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

aks_uses_azure_policies_addon_disabled_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name].addon_profile
	not common_lib.valid_key(cluster, "azure_policy")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].addon_profile.azure_policy' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].addon_profile.azure_policy' should be defined and set to true", [name]), "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s].addon_profile", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name, "addon_profile"], [])}
	# before azurerm 3.0

}

aks_uses_azure_policies_addon_disabled_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name].addon_profile.azure_policy
	cluster.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].addon_profile.azure_policy.enabled' is set to false", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].addon_profile.azure_policy.enabled' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s].addon_profile.azure_policy.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name, "addon_profile", "azure_policy", "enabled"], [])}
	# before azurerm 3.0

}

aks_uses_azure_policies_addon_disabled_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	cluster.azure_policy_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].azure_policy_enabled' is set to false", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].azure_policy_enabled' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s].azure_policy_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name, "azure_policy_enabled"], [])}
	# after azurerm 3.0

}

aks_uses_azure_policies_addon_disabled_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	not common_lib.valid_key(cluster, "addon_profile")
	not common_lib.valid_key(cluster, "azure_policy_enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s]' does not use Azure Policies", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s]' should use Azure Policies", [name]), "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name], [])}
	# before version 3.0
	# after version 3.0

}

# METADATA: library-snippet
# version: v1
# title: "KICS: AKS Uses Azure Policies Add-On Disabled"
# description: >-
#   Azure Container Service (AKS) should use Azure Policies Add-On
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.aks_uses_azure_policies_addon_disabled"
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
aks_uses_azure_policies_addon_disabled_snippet[violation] {
	aks_uses_azure_policies_addon_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
