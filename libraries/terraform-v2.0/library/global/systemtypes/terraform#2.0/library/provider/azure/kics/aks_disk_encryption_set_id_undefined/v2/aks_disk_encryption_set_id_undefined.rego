package global.systemtypes["terraform:2.0"].library.provider.azure.kics.aks_disk_encryption_set_id_undefined.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

aks_disk_encryption_set_id_undefined_inner[result] {
	cluster := input.document[i].resource.azurerm_kubernetes_cluster[name]
	not common_lib.valid_key(cluster, "disk_encryption_set_id")
	is_not_ephemeral(cluster)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_kubernetes_cluster[%s].disk_encryption_set_id' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_kubernetes_cluster[%s].disk_encryption_set_id' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(cluster, name), "resourceType": "azurerm_kubernetes_cluster", "searchKey": sprintf("azurerm_kubernetes_cluster[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_kubernetes_cluster", name], [])}
}

is_not_ephemeral(cluster) {
	not common_lib.valid_key(cluster.default_node_pool, "os_disk_type")
} else {
	disk_type := cluster.default_node_pool.os_disk_type
	disk_type != "Ephemeral"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: AKS Disk Encryption Set ID Undefined"
# description: >-
#   Azure Container Service (AKS) should use Disk Encryption Set ID in supported types of disk
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.aks_disk_encryption_set_id_undefined"
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
#     []
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
aks_disk_encryption_set_id_undefined_snippet[violation] {
	aks_disk_encryption_set_id_undefined_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
