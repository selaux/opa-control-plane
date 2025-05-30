package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.net_raw_capabilities_disabled_for_psp.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

net_raw_capabilities_disabled_for_psp_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	spec := resource.spec
	not commonLib.compareArrays(spec.required_drop_capabilities, ["ALL", "NET_RAW"])
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "spec.required_drop_capabilities 'is not ALL or NET_RAW'", "keyExpectedValue": "spec.required_drop_capabilities 'is ALL or NET_RAW'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.required_drop_capabilities", [name]), "searchLine": commonLib.build_search_line(["resource", "kubernetes_pod_security_policy", name, "spec"], ["required_drop_capabilities"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: NET_RAW Capabilities Disabled for PSP"
# description: >-
#   Containers need to have NET_RAW or All as drop capabilities
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.net_raw_capabilities_disabled_for_psp"
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
net_raw_capabilities_disabled_for_psp_snippet[violation] {
	net_raw_capabilities_disabled_for_psp_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
