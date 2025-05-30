package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.service_account_name_undefined_or_empty.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

service_account_name_undefined_or_empty_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	spec := resource.spec
	not common_lib.valid_key(spec, "service_account_name")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_pod[%s].spec.service_account_name is undefined or null", [name]), "keyExpectedValue": sprintf("kubernetes_pod[%s].spec.service_account_name should be defined and not null", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].spec", [name])}
}

service_account_name_undefined_or_empty_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	service_account_name := resource.spec.service_account_name
	service_account_name == ""
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod[%s].spec.service_account_name is null or empty", [name]), "keyExpectedValue": sprintf("kubernetes_pod[%s].spec.service_account_name is correct", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].spec.service_account_name", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Service Account Name Undefined Or Empty"
# description: >-
#   A Kubernetes Pod should have a Service Account defined so to restrict Kubernetes API access, which means the attribute 'service_account_name' should be defined and not empty.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.service_account_name_undefined_or_empty"
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
service_account_name_undefined_or_empty_snippet[violation] {
	service_account_name_undefined_or_empty_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
