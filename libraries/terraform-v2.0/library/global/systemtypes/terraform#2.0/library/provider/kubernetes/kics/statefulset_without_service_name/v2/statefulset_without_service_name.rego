package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.statefulset_without_service_name.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

statefulset_without_service_name_inner[result] {
	stateful := input.document[i].resource.kubernetes_stateful_set[name]
	count({x | resource := input.document[_].resource.kubernetes_service[x]; resource.spec.cluster_ip == "None"; stateful.metadata.namespace == resource.metadata.namespace; stateful.spec.service_name == resource.metadata.name; match_labels(stateful.spec.template.metadata.labels, resource.spec.selector) == true}) == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_stateful_set[%s].spec.service_name does not refer to a Headless Service", [name]), "keyExpectedValue": sprintf("kubernetes_stateful_set[%s].spec.service_name should refer to a Headless Service", [name]), "resourceName": tf_lib.get_resource_name(stateful, name), "resourceType": "kubernetes_stateful_set", "searchKey": sprintf("kubernetes_stateful_set[%s].spec.service_name", [name])}
}

match_labels(serviceLabels, statefulsetLabels) {
	count({x | label := serviceLabels[x]; label == statefulsetLabels[x]}) == count(serviceLabels)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: StatefulSet Without Service Name"
# description: >-
#   StatefulSets should have an existing headless 'serviceName'. The headless service labels should also be implemented on StatefulSets labels.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.statefulset_without_service_name"
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
statefulset_without_service_name_snippet[violation] {
	statefulset_without_service_name_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
