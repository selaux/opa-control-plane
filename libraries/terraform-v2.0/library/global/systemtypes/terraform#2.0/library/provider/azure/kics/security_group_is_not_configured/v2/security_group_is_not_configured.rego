package global.systemtypes["terraform:2.0"].library.provider.azure.kics.security_group_is_not_configured.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

security_group_is_not_configured_inner[result] {
	resource := input.document[i].resource.azure_virtual_network[name]
	not common_lib.valid_key(resource.subnet, "security_group")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azure_virtual_network[%s].subnet.security_group' is undefined or null", [name]), "keyExpectedValue": sprintf("'azure_virtual_network[%s].subnet.security_group' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azure_virtual_network", "searchKey": sprintf("azure_virtual_network[%s].subnet", [name])}
}

security_group_is_not_configured_inner[result] {
	resource := input.document[i].resource.azure_virtual_network[name]
	count(resource.subnet.security_group) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azure_virtual_network[%s].subnet.security_group' is empty", [name]), "keyExpectedValue": sprintf("'azure_virtual_network[%s].subnet.security_group' should not be empty", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azure_virtual_network", "searchKey": sprintf("azure_virtual_network[%s].subnet.security_group", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Security Group is Not Configured"
# description: >-
#   Azure Virtual Network subnet must be configured with a Network Security Group, which means the attribute 'security_group' must be defined and not empty
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.security_group_is_not_configured"
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
#       identifier: azure_virtual_network
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
security_group_is_not_configured_snippet[violation] {
	security_group_is_not_configured_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
