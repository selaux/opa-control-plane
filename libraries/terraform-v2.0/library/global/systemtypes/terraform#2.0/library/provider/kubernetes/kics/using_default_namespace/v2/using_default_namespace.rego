package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.using_default_namespace.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

listKinds := {"kubernetes_ingress", "kubernetes_config_map", "kubernetes_secret", "kubernetes_service", "kubernetes_cron_job", "kubernetes_service_account", "kubernetes_role", "kubernetes_role_binding", "kubernetes_pod", "kubernetes_deployment", "kubernetes_daemonset", "kubernetes_job", "kubernetes_stateful_set", "kubernetes_replication_controller"}

using_default_namespace_inner[result] {
	resource := input.document[i].resource
	common_lib.valid_key(resource, listKinds[x])
	k8 := resource[listKinds[x]][name]
	not common_lib.valid_key(k8.metadata, "namespace")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].metadata is undefined", [listKinds[x], name]), "keyExpectedValue": sprintf("%s[%s].metadata should be set", [listKinds[x], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": listKinds[x], "searchKey": sprintf("%s[%s].metadata", [listKinds[x], name])}
}

using_default_namespace_inner[result] {
	resource := input.document[i].resource
	resource[listKinds[x]][name].metadata.namespace == "default"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].metadata.namespace is set to 'default'", [listKinds[x], name]), "keyExpectedValue": sprintf("%s[%s].metadata.namespace should not be set to 'default'", [listKinds[x], name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": listKinds[x], "searchKey": sprintf("%s[%s].metadata.namespace", [listKinds[x], name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Using Default Namespace"
# description: >-
#   The default namespace should not be used
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.using_default_namespace"
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
using_default_namespace_snippet[violation] {
	using_default_namespace_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
