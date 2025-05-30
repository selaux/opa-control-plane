package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.rbac_roles_with_read_secrets_permissions.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

readVerbs := ["get", "watch", "list"]

rbac_roles_with_read_secrets_permissions_inner[result] {
	resourceTypes := ["kubernetes_role", "kubernetes_cluster_role"]
	resource := input.document[i].resource[resourceTypes[t]][name]
	allowsSecrets(resource.rule)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Some rule is giving access to 'secrets' resources", "keyExpectedValue": "Rules don't give access to 'secrets' resources", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceTypes[t], "searchKey": sprintf("%s[%s].rule", [resourceTypes[t], name])}
}

allowsSecrets(rules) {
	is_array(rules)
	some r
	rules[r].resources[_] == "secrets"
	rules[r].verbs[_] == readVerbs[_]
}

allowsSecrets(rule) {
	is_object(rule)
	rule.resources[_] == "secrets"
	rule.verbs[_] == readVerbs[_]
}

# METADATA: library-snippet
# version: v1
# title: "KICS: RBAC Roles with Read Secrets Permissions"
# description: >-
#   Roles and ClusterRoles with get/watch/list RBAC permissions on Kubernetes secrets are dangerous and should be avoided. In case of compromise, attackers could abuse these roles to access sensitive data, such as passwords, tokens and keys
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.rbac_roles_with_read_secrets_permissions"
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
rbac_roles_with_read_secrets_permissions_snippet[violation] {
	rbac_roles_with_read_secrets_permissions_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
