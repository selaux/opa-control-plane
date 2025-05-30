package global.systemtypes["terraform:2.0"].library.provider.azure.kics.encryption_on_managed_disk_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

encryption_on_managed_disk_disabled_inner[result] {
	resource := input.document[i].resource
	encryption := resource.azurerm_managed_disk[name]
	not common_lib.valid_key(encryption, "encryption_settings")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("azurerm_managed_disk[%s].encryption_settings is undefined or null", [name]), "keyExpectedValue": sprintf("azurerm_managed_disk[%s].encryption_settings should be defined and not null", [name]), "remediation": "encryption_settings = {\n\t\t enabled= true\n\t}\n", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_managed_disk", "searchKey": sprintf("azurerm_managed_disk[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_managed_disk", name], [])}
}

encryption_on_managed_disk_disabled_inner[result] {
	resource := input.document[i].resource
	encryption := resource.azurerm_managed_disk[name]
	encryption.encryption_settings.enabled == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("azurerm_managed_disk[%s].encryption_settings.enabled is false", [name]), "keyExpectedValue": sprintf("azurerm_managed_disk[%s].encryption_settings.enabled should be true ", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_managed_disk", "searchKey": sprintf("azurerm_managed_disk[%s].encryption_settings.enabled", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_managed_disk", name, "encryption_settings", "enabled"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Encryption On Managed Disk Disabled"
# description: >-
#   Ensure that the encryption is active on the disk
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.encryption_on_managed_disk_disabled"
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
#       identifier: azurerm_managed_disk
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
encryption_on_managed_disk_disabled_snippet[violation] {
	encryption_on_managed_disk_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
