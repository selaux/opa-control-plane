package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.deployment_has_no_pod_anti_affinity.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

deployment_has_no_pod_anti_affinity_inner[result] {
	resource := input.document[i].resource.kubernetes_deployment[name]
	resource.spec.replicas > 2
	not common_lib.valid_key(resource.spec.template.spec, "affinity")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_deployment", "searchKey": sprintf("kubernetes_deployment[%s].spec.template.spec", [name])}
}

deployment_has_no_pod_anti_affinity_inner[result] {
	resource := input.document[i].resource.kubernetes_deployment[name]
	resource.spec.replicas > 2
	affinity := resource.spec.template.spec.affinity
	not common_lib.valid_key(affinity, "pod_anti_affinity")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_deployment", "searchKey": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity", [name])}
}

deployment_has_no_pod_anti_affinity_inner[result] {
	resource := input.document[i].resource.kubernetes_deployment[name]
	resource.spec.replicas > 2
	affinity := resource.spec.template.spec.affinity
	common_lib.valid_key(affinity, "pod_anti_affinity")
	podAntiAffinity := affinity.pod_anti_affinity
	not common_lib.valid_key(podAntiAffinity, "preferred_during_scheduling_ignored_during_execution")
	not common_lib.valid_key(podAntiAffinity, "required_during_scheduling_ignored_during_execution")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.required_during_scheduling_ignored_during_execution and/or kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.preferred_during_scheduling_ignored_during_execution are undefined", [name, name]), "keyExpectedValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.required_during_scheduling_ignored_during_execution and/or kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.preferred_during_scheduling_ignored_during_execution should be set", [name, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_deployment", "searchKey": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity", [name])}
}

deployment_has_no_pod_anti_affinity_inner[result] {
	resource := input.document[i].resource.kubernetes_deployment[name]
	resource.spec.replicas > 2
	affinity := resource.spec.template.spec.affinity
	common_lib.valid_key(affinity, "pod_anti_affinity")
	podAntiAffinity := affinity.pod_anti_affinity
	common_lib.valid_key(podAntiAffinity, "preferred_during_scheduling_ignored_during_execution")
	pref := podAntiAffinity.preferred_during_scheduling_ignored_during_execution
	object.get(pref.pod_affinity_term, "topology_key", "undefined") != "kubernetes.io/hostname"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.preferred_during_scheduling_ignored_during_execution.pod_affinity_term.topology_key is invalid or undefined", [name]), "keyExpectedValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.preferred_during_scheduling_ignored_during_execution.pod_affinity_term.topology_key should be set to 'kubernetes.io/hostname'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_deployment", "searchKey": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity", [name])}
}

deployment_has_no_pod_anti_affinity_inner[result] {
	resource := input.document[i].resource.kubernetes_deployment[name]
	resource.spec.replicas > 2
	affinity := resource.spec.template.spec.affinity
	common_lib.valid_key(affinity, "pod_anti_affinity")
	podAntiAffinity := affinity.pod_anti_affinity
	common_lib.valid_key(podAntiAffinity, "preferred_during_scheduling_ignored_during_execution")
	pref := podAntiAffinity.preferred_during_scheduling_ignored_during_execution
	object.get(pref.pod_affinity_term, "topology_key", "undefined") == "kubernetes.io/hostname"
	templateLabels := resource.spec.template.metadata.labels
	selectorLabels := pref.pod_affinity_term.label_selector.match_labels
	match_labels(templateLabels, selectorLabels) == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.preferred_during_scheduling_ignored_during_execution.pod_affinity_term.label_selector.match_labels don't match any label on template metadata", [name]), "keyExpectedValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.preferred_during_scheduling_ignored_during_execution.pod_affinity_term.label_selector.match_labels match any label on template metadata", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_deployment", "searchKey": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity", [name])}
}

deployment_has_no_pod_anti_affinity_inner[result] {
	resource := input.document[i].resource.kubernetes_deployment[name]
	resource.spec.replicas > 2
	affinity := resource.spec.template.spec.affinity
	common_lib.valid_key(affinity, "pod_anti_affinity")
	podAntiAffinity := affinity.pod_anti_affinity
	common_lib.valid_key(podAntiAffinity, "required_during_scheduling_ignored_during_execution")
	pref := podAntiAffinity.required_during_scheduling_ignored_during_execution
	object.get(pref, "topology_key", "undefined") != "kubernetes.io/hostname"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.required_during_scheduling_ignored_during_execution[%d].topology_key is invalid or undefined", [name]), "keyExpectedValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.required_during_scheduling_ignored_during_execution[%d].topology_key should be set to 'kubernetes.io/hostname'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_deployment", "searchKey": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity", [name])}
}

deployment_has_no_pod_anti_affinity_inner[result] {
	resource := input.document[i].resource.kubernetes_deployment[name]
	resource.spec.replicas > 2
	affinity := resource.spec.template.spec.affinity
	common_lib.valid_key(affinity, "pod_anti_affinity")
	podAntiAffinity := affinity.pod_anti_affinity
	common_lib.valid_key(podAntiAffinity, "required_during_scheduling_ignored_during_execution")
	pref := podAntiAffinity.required_during_scheduling_ignored_during_execution
	object.get(pref, "topology_key", "undefined") == "kubernetes.io/hostname"
	templateLabels := resource.spec.template.metadata.labels
	selectorLabels := pref.label_selector.match_labels
	match_labels(templateLabels, selectorLabels) == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.required_during_scheduling_ignored_during_execution.label_selector.match_labels don't match any label on template metadata", [name]), "keyExpectedValue": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity.pod_anti_affinity.required_during_scheduling_ignored_during_execution.label_selector.match_labels match any label on template metadata", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_deployment", "searchKey": sprintf("kubernetes_deployment[%s].spec.template.spec.affinity", [name])}
}

match_labels(templateLabels, selectorLabels) {
	some Key
	templateLabels[Key] == selectorLabels[Key]
} else = false

# METADATA: library-snippet
# version: v1
# title: "KICS: Deployment Has No PodAntiAffinity"
# description: >-
#   Check if Deployment resources don't have a podAntiAffinity policy, which prevents multiple pods from being scheduled on the same node.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.deployment_has_no_pod_anti_affinity"
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
deployment_has_no_pod_anti_affinity_snippet[violation] {
	deployment_has_no_pod_anti_affinity_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
