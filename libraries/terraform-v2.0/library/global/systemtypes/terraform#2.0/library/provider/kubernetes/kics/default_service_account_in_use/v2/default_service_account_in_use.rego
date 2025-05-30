package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.default_service_account_in_use.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

default_service_account_in_use_inner[result] {
	resource := input.document[i].resource.kubernetes_service_account[name]
	resource.metadata.name == "default"
	not common_lib.valid_key(resource, "automount_service_account_token")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_service_account[%s].automount_service_account_token is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_service_account[%s].automount_service_account_token should be set", [name]), "remediation": "automount_service_account_token = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_service_account", "searchKey": sprintf("kubernetes_service_account[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "kubernetes_service_account", name], [])}
}

default_service_account_in_use_inner[result] {
	resource := input.document[i].resource.kubernetes_service_account[name]
	resource.metadata.name == "default"
	resource.automount_service_account_token == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_service_account[%s].automount_service_account_token is not set to false", [name]), "keyExpectedValue": sprintf("kubernetes_service_account[%s].automount_service_account_token should be set to false", [name]), "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_service_account", "searchKey": sprintf("kubernetes_service_account[%s].automount_service_account_token", [name]), "searchLine": common_lib.build_search_line(["resource", "kubernetes_service_account", name], ["automount_service_account_token"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Default Service Account In Use"
# description: >-
#   Default service accounts should not be actively used
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.default_service_account_in_use"
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
#     name: "kubernetes"
#     versions:
#       min: "v2"
#       max: "v2"
#   rule_targets:
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
default_service_account_in_use_snippet[violation] {
	default_service_account_in_use_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
