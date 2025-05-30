package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.missing_app_armor_config.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

missing_app_armor_config_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	metadata := resource.metadata
	metadata.annotations[key]
	expectedKey := "container.apparmor.security.beta.kubernetes.io"
	not startswith(key, expectedKey)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_pod[%s].metadata.annotations doesn't contain AppArmor profile config: '%s'", [name, expectedKey]), "keyExpectedValue": sprintf("kubernetes_pod[%s].metadata.annotations should contain AppArmor profile config: '%s'", [name, expectedKey]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].metadata.annotations", [name])}
}

missing_app_armor_config_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	metadata := resource.metadata
	not metadata.annotations
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("kubernetes_pod[%s].metadata doesn't contain AppArmor profile config in annotations", [name]), "keyExpectedValue": sprintf("kubernetes_pod[%s].metadata should include annotations for AppArmor profile config", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].metadata", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Missing App Armor Config"
# description: >-
#   Containers should be configured with AppArmor for any application to reduce its potential attack
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.missing_app_armor_config"
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
missing_app_armor_config_snippet[violation] {
	missing_app_armor_config_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
