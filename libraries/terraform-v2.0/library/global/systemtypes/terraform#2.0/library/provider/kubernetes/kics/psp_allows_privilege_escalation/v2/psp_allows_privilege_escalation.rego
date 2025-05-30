package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.psp_allows_privilege_escalation.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

psp_allows_privilege_escalation_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	not common_lib.valid_key(resource.spec, "allow_privilege_escalation")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_pod_security_policy[%s].spec.allow_privilege_escalation is undefined", [name]), "keyExpectedValue": sprintf("kubernetes_pod_security_policy[%s].spec.allow_privilege_escalation should be set", [name]), "remediation": "allow_privilege_escalation = false", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec", [name]), "searchLine": common_lib.build_search_line(["resource", "kubernetes_pod_security_policy", name, "spec"], [])}
}

psp_allows_privilege_escalation_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	resource.spec.allow_privilege_escalation != false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod_security_policy[%s].spec.allow_privilege_escalation is set to true", [name]), "keyExpectedValue": sprintf("kubernetes_pod_security_policy[%s].spec.allow_privilege_escalation should be set to false", [name]), "remediation": json.marshal({"after": "false", "before": sprintf("%s", [resource.spec.allow_privilege_escalation])}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.allow_privilege_escalation", [name]), "searchLine": common_lib.build_search_line(["resource", "kubernetes_pod_security_policy", name, "spec"], ["allow_privilege_escalation"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: PSP Allows Privilege Escalation"
# description: >-
#   PodSecurityPolicy should not allow privilege escalation
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.psp_allows_privilege_escalation"
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
psp_allows_privilege_escalation_snippet[violation] {
	psp_allows_privilege_escalation_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
