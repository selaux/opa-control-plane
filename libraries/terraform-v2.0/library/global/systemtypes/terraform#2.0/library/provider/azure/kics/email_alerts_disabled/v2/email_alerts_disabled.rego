package global.systemtypes["terraform:2.0"].library.provider.azure.kics.email_alerts_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

email_alerts_disabled_inner[result] {
	resource := input.document[i].resource.azurerm_security_center_contact[name]
	resource.alert_notifications == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_security_center_contact.%s.alert_notifications' is false", [name]), "keyExpectedValue": sprintf("'azurerm_security_center_contact.%s.alert_notifications' should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_security_center_contact", "searchKey": sprintf("azurerm_security_center_contact[%s].alert_notifications", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_security_center_contact", name, "alert_notifications"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Email Alerts Disabled"
# description: >-
#   Make sure that alerts notifications are set to 'On' in the Azure Security Center Contact
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.email_alerts_disabled"
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
email_alerts_disabled_snippet[violation] {
	email_alerts_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
