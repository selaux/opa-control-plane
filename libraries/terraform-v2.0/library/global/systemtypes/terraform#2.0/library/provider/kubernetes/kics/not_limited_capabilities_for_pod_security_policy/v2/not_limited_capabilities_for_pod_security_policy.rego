package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.not_limited_capabilities_for_pod_security_policy.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

not_limited_capabilities_for_pod_security_policy_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	not common_lib.valid_key(resource.spec, "required_drop_capabilities")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_pod_security_policy[%s].spec.required_drop_capabilities is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_pod_security_policy[%s].spec.required_drop_capabilities should be set", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Not Limited Capabilities For Pod Security Policy"
# description: >-
#   Limit capabilities for a Pod Security Policy
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.not_limited_capabilities_for_pod_security_policy"
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
not_limited_capabilities_for_pod_security_policy_snippet[violation] {
	not_limited_capabilities_for_pod_security_policy_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
