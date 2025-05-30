package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.workload_host_port_not_specified.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

workload_host_port_not_specified_inner[result] {
	types := {"kubernetes_deployment": "spec.template.spec.container", "kubernetes_pod": "spec.container"}
	resource_prefix := types[x]
	resource := input.document[i].resource[x][name]
	path := checkPath(resource)
	not common_lib.valid_key(path.port, "host_port")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'host_port' is undefined or null", "keyExpectedValue": "Attribute 'host_port' should be defined and not null", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": x, "searchKey": sprintf("%s[%s].%s.port", [x, name, resource_prefix])}
}

checkPath(resource) = path {
	path := resource.spec.template.spec.container
} else = path {
	path := resource.spec.container
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Workload Host Port Not Specified"
# description: >-
#   Verifies if Kubernetes workload's host port is specified
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.workload_host_port_not_specified"
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
workload_host_port_not_specified_snippet[violation] {
	workload_host_port_not_specified_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
