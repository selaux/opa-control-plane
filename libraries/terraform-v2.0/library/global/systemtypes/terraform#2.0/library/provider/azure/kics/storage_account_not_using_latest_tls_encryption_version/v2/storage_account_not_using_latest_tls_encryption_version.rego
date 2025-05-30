package global.systemtypes["terraform:2.0"].library.provider.azure.kics.storage_account_not_using_latest_tls_encryption_version.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

storage_account_not_using_latest_tls_encryption_version_inner[result] {
	storage := input.document[i].resource.azurerm_storage_account[name]
	storage.min_tls_version != "TLS1_2"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_storage_account[%s].min_tls_version' is not 'TLS1_2'", [name]), "keyExpectedValue": sprintf("'azurerm_storage_account[%s].min_tls_version' is 'TLS1_2'", [name]), "remediation": json.marshal({"after": "TLS1_2", "before": sprintf("%s", [storage.min_tls_version])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(storage, name), "resourceType": "azurerm_storage_account", "searchKey": sprintf("azurerm_storage_account[%s].min_tls_version", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_storage_account", name, "min_tls_version"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Storage Account Not Using Latest TLS Encryption Version"
# description: >-
#   Ensure Storage Account is using the latest version of TLS encryption
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.storage_account_not_using_latest_tls_encryption_version"
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
#       identifier: azurerm_storage_account
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
storage_account_not_using_latest_tls_encryption_version_snippet[violation] {
	storage_account_not_using_latest_tls_encryption_version_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
