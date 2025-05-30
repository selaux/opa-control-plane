package global.systemtypes["terraform:2.0"].library.provider.azure.iam.owner_role_assignment.v1

import data.global.systemtypes["terraform:2.0"].library.provider.azure.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Azure: IAM: Prohibit assignment of Owner role"
# description: >-
#   Require Azure/IAM role assignment to not have owner role assigned to any principal.
# severity: "medium"
# platform: "terraform"
# resource-type: "azure-iam"
# custom:
#   id: "azure.iam.owner_role_assignment"
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
#     - { scope: "resource", service: "iam", name: "role_assignment", identifier: "azurerm_role_assignment", argument: "role_definition_name" }
# schema:
#   parameters:
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
prohibit_owner_role_assignment[violation] {
	role_assignment[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

role_assignment[violation_obj] {
	iam := util.role_assignment_resource_changes[_]
	iam.change.after.role_definition_name == "Owner"

	violation_obj := {
		"message": sprintf("IAM Role Assignment %v with Owner role assigned is prohibited.", [iam.address]),
		"resource": iam,
		"context": {"role_definition_name": iam.change.after.role_definition_name},
	}
}
