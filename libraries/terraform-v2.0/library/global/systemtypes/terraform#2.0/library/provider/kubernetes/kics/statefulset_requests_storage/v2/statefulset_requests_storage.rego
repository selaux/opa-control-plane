package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.statefulset_requests_storage.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

statefulset_requests_storage_inner[result] {
	resource := input.document[i].resource.kubernetes_stateful_set[name]
	volume_claim_template := resource.spec.volume_claim_template
	storage := volume_claim_template.spec.resources.requests.storage
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_stateful_set[%s].spec.volume_claim_template.spec.resources.requests.storage is set to %s", [name, storage]), "keyExpectedValue": sprintf("kubernetes_stateful_set[%s].spec.volume_claim_template.spec.resources.requests.storage should not be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_stateful_set", "searchKey": sprintf("kubernetes_stateful_set[%s].spec.volume_claim_template.spec.resources.requests.storage", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: StatefulSet Requests Storage"
# description: >-
#   A StatefulSet requests volume storage.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.statefulset_requests_storage"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
statefulset_requests_storage_snippet[violation] {
	statefulset_requests_storage_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
