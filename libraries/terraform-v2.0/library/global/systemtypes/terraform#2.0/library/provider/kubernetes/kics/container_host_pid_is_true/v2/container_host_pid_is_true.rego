package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.container_host_pid_is_true.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

container_host_pid_is_true_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	specInfo.spec.host_pid == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'host_pid' is true", "keyExpectedValue": "Attribute 'host_pid' should be undefined or false", "remediation": json.marshal({"after": "false", "before": "true"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.host_pid", [resourceType, name, specInfo.path]), "searchLine": common_lib.build_search_line([resourceType, name, specInfo.path], ["host_pid"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Container Host Pid Is True"
# description: >-
#   Minimize the admission of containers wishing to share the host process ID namespace
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.container_host_pid_is_true"
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
container_host_pid_is_true_snippet[violation] {
	container_host_pid_is_true_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
