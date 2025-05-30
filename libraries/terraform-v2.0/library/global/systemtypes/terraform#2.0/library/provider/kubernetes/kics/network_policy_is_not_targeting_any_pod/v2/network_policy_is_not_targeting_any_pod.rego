package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.network_policy_is_not_targeting_any_pod.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

network_policy_is_not_targeting_any_pod_inner[result] {
	resource := input.document[i].resource.kubernetes_network_policy[name]
	common_lib.valid_key(resource.spec.pod_selector, "match_labels")
	targetLabels := resource.spec.pod_selector.match_labels
	labelValue := targetLabels[key]
	not hasReference(labelValue)
	not findTargettedPod(labelValue, key)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_network_policy[%s].spec.pod_selector.match_labels is not targeting any pod", [name]), "keyExpectedValue": sprintf("kubernetes_network_policy[%s].spec.pod_selector.match_labels is targeting at least a pod", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_network_policy", "searchKey": sprintf("kubernetes_network_policy[%s].spec.pod_selector.match_labels", [name])}
}

findTargettedPod(lValue, lKey) {
	pod := input.document[_].resource[resourceType]
	resourceType != "kubernetes_network_policy"
	labels := pod[podName].metadata.labels

	some key
	key == lKey
	labels[key] == lValue
} else = false

hasReference(label) {
	regex.match("kubernetes_[_a-zA-Z]+.[a-zA-Z-_0-9]+", label)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Network Policy Is Not Targeting Any Pod"
# description: >-
#   Check if any network policy is not targeting any pod.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.network_policy_is_not_targeting_any_pod"
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
network_policy_is_not_targeting_any_pod_snippet[violation] {
	network_policy_is_not_targeting_any_pod_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
