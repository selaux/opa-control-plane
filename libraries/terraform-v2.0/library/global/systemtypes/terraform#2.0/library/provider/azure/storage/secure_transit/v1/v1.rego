package global.systemtypes["terraform:2.0"].library.provider.azure.storage.secure_transit.v1

import data.global.systemtypes["terraform:2.0"].library.provider.azure.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Azure: Storage Account: Deny Unencrypted transit"
# description: >-
#   Azure/Storage Account should accept requests from secure connections (https) only.
# severity: "medium"
# platform: "terraform"
# resource-type: "azure-storage_account"
# custom:
#   id: "azure.storage.secure_transit"
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
#     - { scope: "resource", service: "storage", name: "storage_account", identifier: "azurerm_storage_account", argument: "enable_https_traffic_only" }
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
restrict_storage_account_unecrypted_transit[violation] {
	enable_https_traffic_only[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

enable_https_traffic_only[violation] {
	storage_account := util.storage_account_resource_changes[_]
	storage_account.change.after.enable_https_traffic_only == false

	violation := {
		"message": sprintf("Storage Account %v accepts traffic from unsecured connections (http).", [storage_account.address]),
		"resource": storage_account,
		"context": {"enable_https_traffic_only": storage_account.change.after.enable_https_traffic_only},
	}
}
