package library.v1.kubernetes.admission.rbac.v1

import data.library.parameters
import data.library.v1.kubernetes.admission.util.v1 as util
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Cluster Roles: Prohibit Wildcard API Groups"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Require cluster roles to be granted access to specific API groups without using wildcards.

deny_clusterrole_create_wildcard_api_groups[reason] {
	utils.kind_matches({"ClusterRole"})
	modify_operation[op]
	input.request.operation == op
	api := input.request.object.rules[_].apiGroups[_]
	api == "*"
	reason := sprintf("Cluster role %v must be granted access to specific API groups without using wildcards.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Roles: Prohibit Wildcard API Groups"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Require roles to be granted access to specific API groups without
#   using wildcards.

deny_role_create_wildcard_api_groups[reason] {
	utils.kind_matches({"Role"})
	modify_operation[op]
	input.request.operation == op
	api := input.request.object.rules[_].apiGroups[_]
	api == "*"
	reason := sprintf("Role %v must be granted access to specific API groups without using wildcards.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Roles: Prohibit Wildcard Verbs"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Require roles to be granted access to each API verb without using wildcards.

deny_role_create_wildcard_verbs[reason] {
	utils.kind_matches({"Role"})
	modify_operation[op]
	input.request.operation == op
	verb := input.request.object.rules[_].verbs[_]
	verb == "*"
	reason := sprintf("Role %v must be granted access to API verbs without using wildcards.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Cluster Roles: Prohibit Wildcard Resources"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Require cluster roles to be granted access to each resource without using wildcards.

deny_clusterrole_create_wildcard_resources[reason] {
	utils.kind_matches({"ClusterRole"})
	modify_operation[op]
	input.request.operation == op
	resource := input.request.object.rules[_].resources[_]
	resource == "*"
	reason := sprintf("Cluster role %v must be granted access to resources without using wildcards.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Roles: Prohibit Wildcard Resources"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Require roles to be granted access to each resource without using wildcards.

deny_role_create_wildcard_resources[reason] {
	utils.kind_matches({"Role"})
	modify_operation[op]
	input.request.operation == op
	resource := input.request.object.rules[_].resources[_]
	resource == "*"
	reason := sprintf("Role %v must be granted access to resources without using wildcards.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Service Accounts: Prohibit Namespaces"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Prevent service accounts from being created or updated in prohibited namespaces.
# schema:
#   type: object
#   properties:
#     prohibited_namespaces:
#       type: array
#       title: "Namespaces (Example: test)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_namespaces

blacklist_namespace_serviceaccounts[reason] {
	count(parameters.prohibited_namespaces) > 0
	not util.is_service_account
	utils.kind_matches({"ServiceAccount"})
	util.modify_ops[ops]
	ops == input.request.operation
	black_item := parameters.prohibited_namespaces[_]
	black_item == input.request.object.metadata.namespace
	reason := sprintf("Service account %v cannot be created in the prohibited namespace.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Cluster Roles: Prohibit Updates from Specified Users"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Prevent the specified users from creating or updating cluster roles.
# schema:
#   type: object
#   properties:
#     prohibited_users:
#       type: array
#       title: "User names (Example: alice)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_users

deny_clusterrole_create_blacklist_userinfo[reason] {
	count(parameters.prohibited_users) > 0
	utils.kind_matches({"ClusterRole"})
	util.modify_ops[ops]
	ops == input.request.operation
	parameters.prohibited_users[input.request.userInfo.username]
	reason := sprintf("User %v is not authorized to modify cluster role %v.", [input.request.userInfo.username, utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Cluster Roles: Restrict Updates to Approved Users"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Allow only the approved users to create or update cluster roles.
# schema:
#   type: object
#   properties:
#     approved_users:
#       type: array
#       title: "User names (Example: alice)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_users

deny_clusterrole_create_non_whitelist_userinfo[reason] {
	count(parameters.approved_users) > 0
	utils.kind_matches({"ClusterRole"})
	util.modify_ops[ops]
	ops == input.request.operation
	not parameters.approved_users[input.request.userInfo.username]
	reason := sprintf("User % v is not authorized to modify cluster role %v.", [input.request.userInfo.username, utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Cluster Role Bindings: Prohibit Wildcard User/Group Names"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Require cluster roles to have each user and group assigned without using wildcards.

deny_clusterrolebinding_create_deny_subject_wildcard[reason] {
	utils.kind_matches({"ClusterRoleBinding"})
	util.modify_ops[ops]
	ops == input.request.operation
	input.request.object.subjects[_].name == "*"
	reason := sprintf("Creating cluster role bindings using wildcards (*) in %v is prohibited.", [utils.input_id])
}

deny_clusterrolebinding_create_deny_subject_wildcard[reason] {
	utils.kind_matches({"ClusterRoleBinding"})
	util.modify_ops[ops]
	ops == input.request.operation
	include_authenticated
	include_unauthenticated
	reason := sprintf("Creating cluster role bindings with public members in %v is prohibited.", [utils.input_id])
}

include_authenticated {
	subject := input.request.object.subjects[_]
	subject.kind == "Group"
	subject.name == "system:authenticated"
	subject.apiGroup == "rbac.authorization.k8s.io"
}

include_unauthenticated {
	subject := input.request.object.subjects[_]
	subject.kind == "Group"
	subject.name == "system:unauthenticated"
	subject.apiGroup == "rbac.authorization.k8s.io"
}

# METADATA: library-snippet
# version: v1
# title: "Cluster Roles: Prohibit Wildcard Verbs"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Require cluster roles to be granted access to each API verb without using wildcards.

deny_clusterrole_create_wildcard_verbs[reason] {
	utils.kind_matches({"ClusterRole"})
	util.modify_ops[ops]
	ops == input.request.operation
	input.request.object.rules[_].verbs[_] == "*"
	reason := sprintf("Cluster role %v must be granted access to API verbs without using wildcards.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Cluster Role Bindings: Prohibit Cluster Roles"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Prevent cluster role bindings from using prohibited roles.
# schema:
#   type: object
#   properties:
#     prohibited_roles:
#       type: array
#       title: "Role (Example: vendor)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_roles

deny_clusterrolebinding_create_blacklist_rolename[reason] {
	count(parameters.prohibited_roles) > 0
	utils.kind_matches({"ClusterRoleBinding"})
	util.modify_ops[ops]
	ops == input.request.operation
	parameters.prohibited_roles[input.request.object.roleRef.name]
	reason := sprintf("Cluster role binding cannot be created using the prohibited role %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Role Bindings: Prohibit Cluster Roles"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Prevent role bindings from using prohibited ClusterRoles.
# schema:
#   type: object
#   properties:
#     prohibited_roles:
#       type: array
#       title: "Cluster Role (Example: vendor)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_roles

deny_rolebinding_create_blacklist_rolename[reason] {
	count(parameters.prohibited_roles) > 0
	utils.kind_matches({"RoleBinding"})
	input.request.object.roleRef.kind == "ClusterRole"
	util.modify_ops[ops]
	ops == input.request.operation
	parameters.prohibited_roles[input.request.object.roleRef.name]
	reason := sprintf("Role binding cannot be created using the prohibited role %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "NetworkPolicy: Restrict Operations to Specified Users"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Require that only specified users be allowed to perform specific operations.
# schema:
#   type: object
#   properties:
#     approved_users:
#       type: object
#       title: Allowed operations
#       patternNames:
#         title: "Operations (Example: CREATE)"
#       additionalProperties:
#         type: array
#         title: "User names as glob syntax (Example: team-*-test)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_users

whitelist_resource_owner_networkpolicy[reason] {
	count(parameters.approved_users) > 0

	# This allows enforcing on different network plugins
	utils.kind_matches({"NetworkPolicy"})

	user := input.request.userInfo.username
	not whitelisted(user, input.request.operation, parameters)
	reason := sprintf("User %v is not authorized to perform operation %v.", [user, input.request.operation])
}

whitelisted(name, action, params) {
	params.approved_users[action][name]
}

# METADATA: library-snippet
# version: v1
# title: "Roles: Prohibit Pod Shell Access"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Prohibit roles and cluster roles from being created with the capability to access pod shells.

deny_role_create_exec_pods[reason] {
	utils.kind_matches({"ClusterRole", "Role"})
	input.request.operation == "CONNECT"
	get_pods
	exec_pods
	reason := "Roles and cluster roles are not authorized to access pod shells."
}

exec_pods {
	rule := input.request.object.rules[_]
	resource := rule.resources[_]
	resource == "pods/exec"
	verb := rule.verbs[_]
	verb == "create"
}

get_pods {
	rule := input.request.object.rules[_]
	resource := rule.resources[_]
	resource == "pods"
	verb := rule.verbs[_]
	verb == "get"
}

# METADATA: library-snippet
# version: v1
# title: "Cluster Roles: Prohibit Name Prefixes"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Prevent cluster roles from being created with specific name prefixes such as `system`.
# schema:
#   type: object
#   properties:
#     prohibited_name_prefixes:
#       type: array
#       title: "Prefixes (Example: system:)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_name_prefixes

deny_role_name_blacklist_prefix[reason] {
	count(parameters.prohibited_name_prefixes) > 0
	utils.kind_matches({"ClusterRole"})
	modify_operation[op]
	input.request.operation == op
	item := parameters.prohibited_name_prefixes[_]
	startswith(input.request.object.metadata.name, item)
	reason := sprintf("Cluster role %v cannot be created with the prohibited name prefix %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Cluster Role Bindings: Prohibit Built-In Role Modifications"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Prevent privileged built-in roles, such as `admin` and `cluster-admin`, from being modified.

deny_cluster_role_binding_sensitive_roles[reason] {
	utils.kind_matches({"ClusterRoleBinding"})
	modify_operation[op]
	input.request.operation == op
	cluster_role := input.request.object.roleRef
	cluster_role.kind == "ClusterRole"
	cluster_role.apiGroup == "rbac.authorization.k8s.io"
	sensitive_roles[cluster_role.name]
	reason := sprintf("Resource %v cannot modify the role binding for privileged built-in roles.", [utils.input_id])
}

sensitive_roles = {
	# https://kubernetes.io/docs/reference/access-authn-authz/rbac/#discovery-roles
	"system:basic-user",
	"system:discovery",
	"system:public-info-viewer",
	# https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles
	"cluster-admin",
	"admin",
	"edit",
	"view",
	# https://kubernetes.io/docs/reference/access-authn-authz/rbac/#core-component-roles
	"system:kube-scheduler",
	"system:volume-scheduler",
	"system:kube-controller-manager",
	"system:node",
	"system:node-proxier",
	"system:auth-delegator",
	"system:heapster",
	"system:kube-aggregator",
	"system:kube-dns",
	"system:kubelet-api-admin",
	"system:node-bootstrapper",
	"system:node-problem-detector",
	"system:persistent-volume-provisioner",
	# https://kubernetes.io/docs/reference/access-authn-authz/rbac/#controller-roles
	"system:controller:attachdetach-controller",
	"system:controller:certificate-controller",
	"system:controller:clusterrole-aggregation-controller",
	"system:controller:cronjob-controller",
	"system:controller:daemon-set-controller",
	"system:controller:deployment-controller",
	"system:controller:disruption-controller",
	"system:controller:endpoint-controller",
	"system:controller:expand-controller",
	"system:controller:generic-garbage-collector",
	"system:controller:horizontal-pod-autoscaler",
	"system:controller:job-controller",
	"system:controller:namespace-controller",
	"system:controller:node-controller",
	"system:controller:persistent-volume-binder",
	"system:controller:pod-garbage-collector",
	"system:controller:pv-protection-controller",
	"system:controller:pvc-protection-controller",
	"system:controller:replicaset-controller",
	"system:controller:replication-controller",
	"system:controller:resourcequota-controller",
	"system:controller:root-ca-cert-publisher",
	"system:controller:route-controller",
	"system:controller:service-account-controller",
	"system:controller:service-controller",
	"system:controller:statefulset-controller",
	"system:controller:ttl-controller",
}

# METADATA: library-snippet
# version: v1
# title: "Encryption: Restrict Configuration to Specific Users"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Allow encryption to be configured only by approved users.
# schema:
#   type: object
#   properties:
#     approved_users:
#       type: array
#       title: "Usernames (Example: alice)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_users

check_encryptionconfig_user[reason] {
	count(parameters.approved_users) > 0
	utils.kind_matches({"EncryptionConfiguration"})
	modify_operation[op]
	input.request.operation == op
	not parameters.approved_users[input.request.userInfo.username]
	reason := sprintf("Encryption %v can only be configured by an approved user.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Encryption: Restrict Configuration to Specific Groups"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Allow encryption to be configured only by approved groups.
# schema:
#   type: object
#   properties:
#     approved_groups:
#       type: array
#       title: "Groups (Example: managers)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_groups

check_encryptionconfig_group[reason] {
	count(parameters.approved_groups) > 0
	utils.kind_matches({"EncryptionConfiguration"})
	modify_operation[op]
	input.request.operation == op
	intersection := input.request.userInfo.groups & parameters.approved_groups
	not count(intersection) > 0
	reason := sprintf("Encryption %v can only be configured by members of an approved group.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Audits: Restrict Users"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Allow dynamic audit webhook backends (`AuditSink` resources) to be created only by approved users.
# schema:
#   type: object
#   properties:
#     approved_users:
#       type: array
#       title: "Usernames (Example: alice)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_users

check_audit_sink_user[reason] {
	count(parameters.approved_users) > 0
	utils.kind_matches({"AuditSink"})
	modify_operation[op]
	input.request.operation == op
	not parameters.approved_users[input.request.userInfo.username]
	reason := sprintf("AuditSink %v can only be created by an approved user.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Audits: Restrict Groups"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Allow dynamic audit webhook backends (`AuditSink` resources) to be created only by approved groups.
# schema:
#   type: object
#   properties:
#     approved_groups:
#       type: array
#       title: "Groups (Example: test)"
#       description: >-
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_groups

check_audit_sink_group[reason] {
	count(parameters.approved_groups) > 0
	utils.kind_matches({"AuditSink"})
	modify_operation[op]
	input.request.operation == op
	intersection := input.request.userInfo.groups & parameters.approved_groups
	not count(intersection) > 0
	reason := sprintf("AuditSink %v can only be created by an approved group.", [utils.input_id])
}

modify_operation = {"UPDATE", "CREATE"}

# METADATA: library-snippet
# version: v1
# title: "Role-Based Access Control (RBAC): Restrict Roles to Protect OPA Webhook"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "rbac"
# description: >-
#   Allow an approved list of ClusterRoles with permissions of create, update, or delete
#   `validatingwebhookconfigurations`, `mutatingwebhookconfigurations` kinds.
# schema:
#   type: object
#   properties:
#     approved_roles:
#       type: array
#       title: "ClusterRoles (Example: cluster-admin, webhook-editor)"
#       description: >-
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_roles

allow_whitelist_roles_of_webhook_editors[reason] {
	count(parameters.approved_roles) > 0
	utils.kind_matches({"ClusterRole"})
	not parameters.approved_roles[input.request.object.metadata.name]
	rule := input.request.object.rules[_]
	lower(utils.resource_name_to_kind[lower(rule.resources[_])]) == lower(edit_resources[_])
	lower(rule.verbs[_]) == lower(edit_verbs[_])
	reason := sprintf("%v has permissions to edit validatingwebhookconfigurations / mutatingwebhookconfigurations.", [utils.input_id])
}

edit_verbs = ["create", "update", "patch", "delete", "*"]

edit_resources = ["*", "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"]
