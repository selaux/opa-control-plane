package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.google_project_auto_create_network_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

google_project_auto_create_network_disabled_inner[result] {
	project := input.document[i].resource.google_project[name]
	project.auto_create_network == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_project[%s].auto_create_network is true", [name]), "keyExpectedValue": sprintf("google_project[%s].auto_create_network should be set to false", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(project, name), "resourceType": "google_project", "searchKey": sprintf("google_project[%s].auto_create_network", [name]), "searchLine": common_lib.build_search_line(["resource", "google_project", name], ["auto_create_network"])}
}

google_project_auto_create_network_disabled_inner[result] {
	project := input.document[i].resource.google_project[name]
	not common_lib.valid_key(project, "auto_create_network")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("google_project[%s].auto_create_network is undefined", [name]), "keyExpectedValue": sprintf("google_project[%s].auto_create_network should be set to false", [name]), "remediation": "auto_create_network = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(project, name), "resourceType": "google_project", "searchKey": sprintf("google_project[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "google_project", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Google Project Auto Create Network Disabled"
# description: >-
#   Verifies if the Google Project Auto Create Network is Disabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.google_project_auto_create_network_disabled"
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
#     name: "google"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: google_project
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
google_project_auto_create_network_disabled_snippet[violation] {
	google_project_auto_create_network_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
