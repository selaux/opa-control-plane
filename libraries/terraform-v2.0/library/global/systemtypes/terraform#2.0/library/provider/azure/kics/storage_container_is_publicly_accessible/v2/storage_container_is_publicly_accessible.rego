package global.systemtypes["terraform:2.0"].library.provider.azure.kics.storage_container_is_publicly_accessible.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

storage_container_is_publicly_accessible_inner[result] {
	resource := input.document[i].resource.azurerm_storage_container[name]
	resource.container_access_type != "private"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'container_access_type' is not equal to 'private'", "keyExpectedValue": "'container_access_type' should equal to 'private'", "remediation": json.marshal({"after": "private", "before": sprintf("%s", [resource.container_access_type])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_storage_container", "searchKey": sprintf("azurerm_storage_container[%s].container_access_type", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_storage_container", name, "container_access_type"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Storage Container Is Publicly Accessible"
# description: >-
#   Anonymous, public read access to a container and its blobs are enabled in Azure Blob Storage
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.storage_container_is_publicly_accessible"
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
#       identifier: azurerm_storage_container
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
storage_container_is_publicly_accessible_snippet[violation] {
	storage_container_is_publicly_accessible_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
