package global.systemtypes["terraform:2.0"].library.provider.azure.kics.dashboard_is_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

dashboard_is_enabled_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	profile := cluster.addon_profile
	kube := profile.kube_dashboard
	kube.enabled == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].addon_profile.kube_dashboard.enabled' is true", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].addon_profile.kube_dashboard.enabled' should be set to false or undefined", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s].addon_profile.kube_dashboard.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name, "addon_profile", "kube_dashboard", "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Dashboard Is Enabled"
# description: >-
#   Check if the Kubernetes Dashboard is enabled.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.dashboard_is_enabled"
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
dashboard_is_enabled_snippet[violation] {
	dashboard_is_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
