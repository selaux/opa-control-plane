package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.container_runs_unmasked.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

container_runs_unmasked_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	allowed_proc_mount_types := resource.spec.allowed_proc_mount_types
	allowed_proc_mount_types[_] == "Unmasked"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "allowed_proc_mount_types contains the value Unmasked", "keyExpectedValue": "allowed_proc_mount_types should contain the value Default", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.allowed_proc_mount_types", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Container Runs Unmasked"
# description: >-
#   Check if a container has full access (unmasked) to the host’s /proc command, which would allow to retrieve sensitive information and possibly change the kernel parameters in runtime.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.container_runs_unmasked"
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
container_runs_unmasked_snippet[violation] {
	container_runs_unmasked_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
