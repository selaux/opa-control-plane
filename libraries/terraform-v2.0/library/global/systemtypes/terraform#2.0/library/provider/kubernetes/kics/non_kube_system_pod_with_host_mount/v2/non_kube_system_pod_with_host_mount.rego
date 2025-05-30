package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.non_kube_system_pod_with_host_mount.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

non_kube_system_pod_with_host_mount_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	metadata := resource.metadata
	not metadata.namespace
	volumes := resource.spec.volume
	volumes[_0].path
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("Resource name '%s' in non kube-system namespace '%s' has a host_path '%s' mounted", [metadata.name, "default", volumes[j].path]), "keyExpectedValue": sprintf("Resource name '%s' in non kube-system namespace '%s' should not have host_path '%s' mounted", [metadata.name, "default", volumes[j].path]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].spec.volume.host_path.path", [name])}
}

non_kube_system_pod_with_host_mount_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	metadata := resource.metadata
	namespace := metadata.namespace
	namespace != "kube-system"
	volumes := resource.spec.volume
	volumes[_0].path
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("Resource name '%s' in non kube-system namespace '%s' has a host_path '%s' mounted", [metadata.name, metadata.namespace, volumes[j].path]), "keyExpectedValue": sprintf("Resource name '%s' in non kube-system namespace '%s' should not have host_path '%s' mounted", [metadata.name, metadata.namespace, volumes[j].path]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].spec.volume.host_path.path", [name])}
}

non_kube_system_pod_with_host_mount_inner[result] {
	resource := input.document[i].resource.kubernetes_persistent_volume[name]
	metadata := resource.metadata
	not metadata.namespace
	volumes := resource.spec.volume
	volumes[_0].path
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("Resource name '%s' in non kube-system namespace '%s' has a host_path '%s' mounted", [metadata.name, "default", volumes[j].path]), "keyExpectedValue": sprintf("Resource name '%s' in non kube-system namespace '%s' should not have host_path '%s' mounted", [metadata.name, "default", volumes[j].path]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_persistent_volume", "searchKey": sprintf("kubernetes_persistent_volume[%s].spec.volume.host_path.path", [name])}
}

non_kube_system_pod_with_host_mount_inner[result] {
	resource := input.document[i].resource.kubernetes_persistent_volume[name]
	metadata := resource.metadata
	namespace := metadata.namespace
	namespace != "kube-system"
	volumes := resource.spec.volume
	volumes[_0].path
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("Resource name '%s' in non kube-system namespace '%s' has a host_path '%s' mounted", [metadata.name, metadata.namespace, volumes[j].path]), "keyExpectedValue": sprintf("Resource name '%s' in non kube-system namespace '%s' should not have host_path '%s' mounted", [metadata.name, metadata.namespace, volumes[j].path]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_persistent_volume", "searchKey": sprintf("kubernetes_persistent_volume[%s].spec.volume.host_path.path", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Non Kube System Pod With Host Mount"
# description: >-
#   A non kube-system workload should not have hostPath mounted
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.non_kube_system_pod_with_host_mount"
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
non_kube_system_pod_with_host_mount_snippet[violation] {
	non_kube_system_pod_with_host_mount_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
