package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.psp_set_to_privileged.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

psp_set_to_privileged_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	resource.spec.privileged != false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod_security_policy[%s].spec.privileged is not set to false", [name]), "keyExpectedValue": sprintf("kubernetes_pod_security_policy[%s].spec.privileged should be set to false", [name]), "remediation": json.marshal({"after": "false", "before": sprintf("%s", [resource.spec.privileged])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.privileged", [name]), "searchLine": common_lib.build_search_line(["resource", "kubernetes_pod_security_policy", name, "spec"], ["privileged"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: PSP Set To Privileged"
# description: >-
#   Do not allow pod to request execution as privileged.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.psp_set_to_privileged"
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
psp_set_to_privileged_snippet[violation] {
	psp_set_to_privileged_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
