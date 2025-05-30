package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.role_binding_to_default_service_account.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

role_binding_to_default_service_account_inner[result] {
	resource := input.document[i].resource.kubernetes_role_binding[name]
	resource.subject[k].kind == "ServiceAccount"
	resource.subject[k].name == "default"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("resource.kubernetes_role_binding[%s].subject[%d].name is default", [name, k]), "keyExpectedValue": sprintf("resource.kubernetes_role_binding[%s].subject[%d].name should not be default", [name, k]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_role_binding", "searchKey": sprintf("resource.kubernetes_role_binding[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Role Binding To Default Service Account"
# description: >-
#   No role nor cluster role should bind to a default service account
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.role_binding_to_default_service_account"
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
role_binding_to_default_service_account_snippet[violation] {
	role_binding_to_default_service_account_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
