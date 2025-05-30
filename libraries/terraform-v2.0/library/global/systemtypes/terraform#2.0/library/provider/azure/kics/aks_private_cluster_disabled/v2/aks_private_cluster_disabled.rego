package global.systemtypes["terraform:2.0"].library.provider.azure.kics.aks_private_cluster_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

aks_private_cluster_disabled_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	not common_lib.valid_key(cluster, "private_cluster_enabled")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].private_cluster_enabled' is undefined", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].private_cluster_enabled' should be defined and set to true", [name]), "remediation": "private_cluster_enabled = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name], [])}
}

aks_private_cluster_disabled_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	cluster.private_cluster_enabled == false
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].private_cluster_enabled' is set to false", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].private_cluster_enabled' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s].private_cluster_enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name, "private_cluster_enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: AKS Private Cluster Disabled"
# description: >-
#   Azure Kubernetes Service (AKS) API should not be exposed to the internet
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.aks_private_cluster_disabled"
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
aks_private_cluster_disabled_snippet[violation] {
	aks_private_cluster_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
