package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.service_account_allows_access_secrets.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as commonLib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

service_account_allows_access_secrets_inner[result] {
	resources_types := ["kubernetes_role", "kubernetes_cluster_role"]
	resource := input.document[i].resource[resources_types[type]]
	ruleTaint := ["get", "watch", "list", "*"]
	kind := resources_types[type]
	getName := resource[name]
	bindingExists(name, kind)
	contentRule(resource[name].rule, ruleTaint)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].rule.verbs contain one of the following verbs: %s", [resources_types[type], name, ruleTaint]), "keyExpectedValue": sprintf("%s[%s].rule.verbs should not contain the following verbs: %s", [resources_types[type], name, ruleTaint]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resources_types[type], "searchKey": sprintf("%s[%s].rule", [resources_types[type], name])}
}

bindingExists(name, kind) {
	kind == "kubernetes_role"

	resource = input.document[roleBinding].resource.kubernetes_role_binding[kcr_name]
	resource.subject[s].kind == "ServiceAccount"
	resource.role_ref.kind == "Role"
	resource.role_ref.name == name
} else {
	kind == "kubernetes_cluster_role"

	resource = input.document[roleBinding].resource.kubernetes_cluster_role_binding[kcr_name]
	resource.subject[s].kind == "ServiceAccount"
	resource.role_ref.kind == "ClusterRole"
	resource.role_ref.name == name
}

contentRule(rule, ruleTaint) {
	resources := rule.resources
	resources[_] == "secrets"

	verbs := rule.verbs
	commonLib.compareArrays(ruleTaint, verbs)
}

contentRule(rule, ruleTaint) {
	is_array(rule)
	resources := rule[r].resources
	resources[_] == "secrets"

	verbs := rule[r].verbs
	commonLib.compareArrays(ruleTaint, verbs)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Service Account Allows Access Secrets"
# description: >-
#   Kubernetes_role and Kubernetes_cluster_role when bound, should not use get, list or watch as verbs
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.service_account_allows_access_secrets"
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
service_account_allows_access_secrets_snippet[violation] {
	service_account_allows_access_secrets_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
