package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.cluster_admin_role_binding_with_super_user_permissions.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

cluster_admin_role_binding_with_super_user_permissions_inner[result] {
	resource := input.document[i].resource.kubernetes_cluster_role_binding[name]
	resource.role_ref.name == "cluster-admin"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("Resource name '%s' is binding 'cluster-admin' role with superuser permissions", [name]), "keyExpectedValue": sprintf("Resource name '%s' isn't binding 'cluster-admin' role with superuser permissions", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_cluster_role_binding", "searchKey": sprintf("kubernetes_cluster_role_binding[%s].role_ref.name", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cluster Admin Rolebinding With Superuser Permissions"
# description: >-
#   Ensure that the cluster-admin role is only used where required (RBAC)
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.cluster_admin_role_binding_with_super_user_permissions"
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
cluster_admin_role_binding_with_super_user_permissions_snippet[violation] {
	cluster_admin_role_binding_with_super_user_permissions_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
