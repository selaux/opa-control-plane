package global.systemtypes["terraform:2.0"].library.provider.azure.kics.aks_network_policy_misconfigured.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

aks_network_policy_misconfigured_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	profile := cluster.network_profile
	policy := profile.network_policy
	not validPolicy(policy)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].network_profile.network_policy' is %s", [name, policy]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].network_profile.network_policy' should be either 'azure' or 'calico'", [name]), "remediation": json.marshal({"after": "azure", "before": sprintf("%s", [policy])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s].network_profile.network_policy", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name, "network_profile", "network_policy"], [])}
}

aks_network_policy_misconfigured_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	profile := cluster.network_profile
	not common_lib.valid_key(profile, "network_policy")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].network_profile.network_policy' is undefined", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].network_profile.network_policy' should be set to either 'azure' or 'calico'", [name]), "remediation": "network_policy = \"azure\"", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s].network_profile", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name, "network_profile"], [])}
}

aks_network_policy_misconfigured_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	not common_lib.valid_key(cluster, "network_profile")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].network_profile' is undefined", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].network_profile' should be set", [name]), "remediation": "network_profile {\n\t\tnetwork_policy = \"azure\"\n\t}", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name], [])}
}

validPolicy("azure") = true

validPolicy("calico") = true

# METADATA: library-snippet
# version: v1
# title: "KICS: AKS Network Policy Misconfigured"
# description: >-
#   Azure Kubernetes Service should have the proper network policy configuration to ensure the principle of least privileges, which means that 'network_profile.network_policy' should be defined
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.aks_network_policy_misconfigured"
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
aks_network_policy_misconfigured_snippet[violation] {
	aks_network_policy_misconfigured_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
