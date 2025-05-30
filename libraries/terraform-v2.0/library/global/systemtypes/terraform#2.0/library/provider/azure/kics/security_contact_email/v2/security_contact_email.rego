package global.systemtypes["terraform:2.0"].library.provider.azure.kics.security_contact_email.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

security_contact_email_inner[result] {
	scc := input.document[i].resource.azurerm_security_center_contact[name]
	not common_lib.valid_key(scc, "email")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_security_center_contact[%s].email' is undefined or null", [name]), "keyExpectedValue": sprintf("'azurerm_security_center_contact[%s].email' should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(scc, name), "resourceType": "azurerm_security_center_contact", "searchKey": sprintf("azurerm_security_center_contact[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_security_center_contact", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Security Contact Email"
# description: >-
#   Security Contact Email should be defined
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.security_contact_email"
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
#       identifier: azurerm_security_center_contact
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
security_contact_email_snippet[violation] {
	security_contact_email_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
