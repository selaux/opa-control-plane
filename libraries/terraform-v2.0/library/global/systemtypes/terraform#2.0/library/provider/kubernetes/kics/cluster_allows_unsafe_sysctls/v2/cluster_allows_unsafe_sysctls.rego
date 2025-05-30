package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.cluster_allows_unsafe_sysctls.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

cluster_allows_unsafe_sysctls_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	common_lib.valid_key(resource.spec, "allowed_unsafe_sysctls")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod_security_policy[%s].spec.allowed_unsafe_sysctls is set", [name]), "keyExpectedValue": sprintf("kubernetes_pod_security_policy[%s].spec.allowed_unsafe_sysctls should be undefined", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.allowed_unsafe_sysctls", [name])}
}

cluster_allows_unsafe_sysctls_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	sysctl := resource.spec.security_context.sysctl[x].name
	check_unsafe(sysctl)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod[%s].spec.security_context.sysctl[%s].name has an unsafe sysctl", [name, x]), "keyExpectedValue": sprintf("kubernetes_pod[%s].spec.security_context.sysctl[%s].name should not have an unsafe sysctl", [name, x]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].spec.security_context.sysctl", [name])}
}

check_unsafe(sysctl) {
	safeSysctls = {"kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.tcp_syncookies", "net.ipv4.ping_group_range"}
	not safeSysctls[sysctl]
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cluster Allows Unsafe Sysctls"
# description: >-
#   A Kubernetes Cluster must not allow unsafe sysctls, to prevent a pod from having any influence on any other pod on the node, harming the node's health or gaining CPU or memory resources outside of the resource limits of a pod. This means the 'spec.security_context.sysctl' must not have an unsafe sysctls and that the attribute 'allowed_unsafe_sysctls' must be undefined.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.cluster_allows_unsafe_sysctls"
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
cluster_allows_unsafe_sysctls_snippet[violation] {
	cluster_allows_unsafe_sysctls_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
