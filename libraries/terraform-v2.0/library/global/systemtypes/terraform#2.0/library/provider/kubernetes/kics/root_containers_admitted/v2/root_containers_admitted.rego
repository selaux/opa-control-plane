package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.root_containers_admitted.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

root_containers_admitted_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	privilege := {"allow_privilege_escalation", "privileged"}
	resource.spec[privilege[p]] == true
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod_security_policy[%s].spec.%s is set to true", [name, privilege[p]]), "keyExpectedValue": sprintf("kubernetes_pod_security_policy[%s].spec.%s should be set to false", [name, privilege[p]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.%s", [name, privilege[p]])}
}

root_containers_admitted_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	resource.spec.run_as_user.rule != "MustRunAsNonRoot"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod_security_policy[%s].spec.run_as_user.rule is not equal to 'MustRunAsNonRoot'", [name]), "keyExpectedValue": sprintf("kubernetes_pod_security_policy[%s].spec.run_as_user.rule is equal to 'MustRunAsNonRoot'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.run_as_user.rule", [name])}
}

root_containers_admitted_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	groups := {"fs_group", "supplemental_groups"}
	resource.spec[groups[p]].rule != "MustRunAs"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod_security_policy[%s].spec.%s.rule does not limit its ranges", [name, groups[p]]), "keyExpectedValue": sprintf("kubernetes_pod_security_policy[%s].spec.%s.rule limits its ranges", [name, groups[p]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.%s.rule", [name, groups[p]])}
}

root_containers_admitted_inner[result] {
	resource := input.document[i].resource.kubernetes_pod_security_policy[name]
	groups := {"fs_group", "supplemental_groups"}
	resource.spec[groups[p]].rule == "MustRunAs"
	resource.spec[groups[p]].range.min == 0
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod_security_policy[%s].spec.%s.range.min allows range '0' (root)", [name, groups[p]]), "keyExpectedValue": sprintf("kubernetes_pod_security_policy[%s].spec.%s.range.min should not allow range '0' (root)", [name, groups[p]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod_security_policy", "searchKey": sprintf("kubernetes_pod_security_policy[%s].spec.%s.range.min", [name, groups[p]])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Root Containers Admitted"
# description: >-
#   Containers must not be allowed to run with root privileges, which means the attributes 'privileged' and 'allow_privilege_escalation' must be set to false, 'run_as_user.rule' must be set to 'MustRunAsNonRoot', and adding the root group must be forbidden
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.root_containers_admitted"
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
root_containers_admitted_snippet[violation] {
	root_containers_admitted_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
