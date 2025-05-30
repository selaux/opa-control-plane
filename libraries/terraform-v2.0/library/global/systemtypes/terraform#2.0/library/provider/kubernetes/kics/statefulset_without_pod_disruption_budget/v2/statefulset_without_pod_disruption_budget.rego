package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.statefulset_without_pod_disruption_budget.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

statefulset_without_pod_disruption_budget_inner[result] {
	resource := input.document[i].resource.kubernetes_stateful_set[name]
	resource.spec.replicas > 1
	common_lib.valid_key(resource.spec.selector, "match_labels")
	targetLabels := resource.spec.selector.match_labels
	labelValue := targetLabels[key]
	not hasReference(labelValue)
	not hasPodDisruptionBudget(labelValue, key)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_stateful_set[%s].spec.selector.match_labels is not targeted by a PodDisruptionBudget", [name]), "keyExpectedValue": sprintf("kubernetes_stateful_set[%s].spec.selector.match_labels is targeted by a PodDisruptionBudget", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_stateful_set", "searchKey": sprintf("kubernetes_stateful_set[%s].spec.selector.match_labels", [name])}
}

hasPodDisruptionBudget(lValue, lKey) {
	pod := input.document[_].resource[resourceType]
	resourceType == "kubernetes_pod_disruption_budget"

	labels := pod[podName].spec.selector.match_labels

	some key
	key == lKey
	labels[key] == lValue
} else = false

hasReference(label) {
	regex.match("kubernetes_pod_disruption_budget.[a-zA-Z-_0-9]+", label)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: StatefulSet Without PodDisruptionBudget"
# description: >-
#   StatefulSets should be assigned with a PodDisruptionBudget to ensure high availability
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.statefulset_without_pod_disruption_budget"
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
statefulset_without_pod_disruption_budget_snippet[violation] {
	statefulset_without_pod_disruption_budget_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
