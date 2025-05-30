package global.systemtypes["terraform:2.0"].library.provider.azure.kics.web_app_accepting_traffic_other_than_https.v2

import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.azure.kics_libs.terraform as tf_lib

web_app_accepting_traffic_other_than_https_inner[result] {
	resource := input.document[i].resource.azurerm_app_service[name]
	not common_lib.valid_key(resource, "https_only")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("'azurerm_app_service[%s].https_only' is undefined", [name]), "keyExpectedValue": sprintf("'azurerm_app_service[%s].https_only' should be set", [name]), "remediation": "https_only = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_app_service", "searchKey": sprintf("azurerm_app_service[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_app_service", name], [])}
}

web_app_accepting_traffic_other_than_https_inner[result] {
	resource := input.document[i].resource.azurerm_app_service[name]
	resource.https_only != true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("'azurerm_app_service[%s].https_only' is not set to true", [name]), "keyExpectedValue": sprintf("'azurerm_app_service[%s].https_only' should be set to true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "azurerm_app_service", "searchKey": sprintf("azurerm_app_service[%s].https_only", [name]), "searchLine": common_lib.build_search_line(["resource", "azurerm_app_service", name, "https_only"], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Web App Accepting Traffic Other Than HTTPS"
# description: >-
#   Web app should only accept HTTPS traffic in Azure Web App Service.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "azure.kics.web_app_accepting_traffic_other_than_https"
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
#       identifier: azurerm_app_service
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
web_app_accepting_traffic_other_than_https_snippet[violation] {
	web_app_accepting_traffic_other_than_https_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
