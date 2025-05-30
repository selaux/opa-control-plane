package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.psp_allows_containers_to_share_the_host_network_namespace.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

psp_allows_containers_to_share_the_host_network_namespace_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	spec := resource.spec
	object.get(spec, "host_network", "undefined") == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'spec.hostNetwork' is true", "keyExpectedValue": "'spec.hostNetwork' should be set to false or undefined", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.host_network", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: PSP Allows Containers To Share The Host Network Namespace"
# description: >-
#   Check if Pod Security Policies allow containers to share the host network namespace.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.psp_allows_containers_to_share_the_host_network_namespace"
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
psp_allows_containers_to_share_the_host_network_namespace_snippet[violation] {
	psp_allows_containers_to_share_the_host_network_namespace_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
