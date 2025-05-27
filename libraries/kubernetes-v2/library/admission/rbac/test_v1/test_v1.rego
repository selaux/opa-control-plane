package library.v1.kubernetes.admission.rbac.test_v1

import data.library.v1.kubernetes.admission.rbac.v1
import data.library.v1.kubernetes.admission.test_objects.v1 as objects

test_k8s_deny_clusterrole_create_wildcard_api_groups_ok {
	in := input_create_cluster_role_more("bob", {"a", "b"}, "ClusterRole", {""}, {"*"})
	actual := v1.deny_clusterrole_create_wildcard_api_groups with input as in

	count(actual) == 0
}

test_k8s_deny_clusterrole_create_wildcard_api_groups_fail {
	in := input_create_cluster_role_more("bob", {"a", "b"}, "ClusterRole", {"*"}, {"*"})
	actual := v1.deny_clusterrole_create_wildcard_api_groups with input as in

	count(actual) == 1
}

test_k8s_deny_role_create_wildcard_api_groups_ok {
	in := input_create_cluster_role_more("bob", {"a", "b"}, "Role", {""}, {"*"})
	actual := v1.deny_role_create_wildcard_api_groups with input as in

	count(actual) == 0
}

test_k8s_deny_role_create_wildcard_api_groups_fail {
	in := input_create_cluster_role_more("bob", {"a", "b"}, "Role", {"*"}, {"*"})
	actual := v1.deny_role_create_wildcard_api_groups with input as in

	count(actual) == 1
}

test_k8s_deny_clusterrole_create_wildcard_resources_ok {
	in := input_create_cluster_role_more("bob", {"a", "b"}, "ClusterRole", {""}, {"something"})
	actual := v1.deny_clusterrole_create_wildcard_resources with input as in

	count(actual) == 0
}

test_k8s_deny_clusterrole_create_wildcard_resources_fail {
	in := input_create_cluster_role_more("bob", {"a", "b"}, "ClusterRole", {""}, {"*"})
	actual := v1.deny_clusterrole_create_wildcard_resources with input as in

	count(actual) == 1
}

test_k8s_deny_role_create_wildcard_resources_ok {
	in := input_create_cluster_role_more("bob", {"a", "b"}, "Role", {""}, {"something"})
	actual := v1.deny_role_create_wildcard_resources with input as in

	count(actual) == 0
}

test_k8s_deny_role_create_wildcard_resources_fail {
	in := input_create_cluster_role_more("bob", {"a", "b"}, "Role", {""}, {"*"})
	actual := v1.deny_role_create_wildcard_resources with input as in

	count(actual) == 1
}

test_k8s_deny_role_create_wildcard_verbs_ok {
	in := input_create_cluster_role_more("bob", {"A", "b"}, "Role", {""}, {"*"})
	actual := v1.deny_role_create_wildcard_verbs with input as in

	count(actual) == 0
}

test_k8s_wildcard_verb {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userInfo": {"username": "alice"},
			"kind": {"kind": "ClusterRole", "group": "rbac.authorization.k8s.io", "version": "v1"},
			"operation": "CREATE",
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "monitoring-endpoints",
					"labels": {"rbac.example.com/aggregate-to-monitoring": "true"},
				},
				"rules": [
					{
						"apiGroups": [""],
						"resources": ["pods"],
						"verbs": ["get"],
					},
					{
						"apiGroups": [""],
						"resources": ["a"],
						"verbs": ["*"],
					},
				],
			},
		},
	}

	actual := v1.deny_clusterrole_create_wildcard_verbs with input as in

	count(actual) == 1
}

test_k8s_deny_role_create_wildcard_verbs_fail {
	in := input_create_cluster_role_more("bob", {"*", "b"}, "Role", {""}, {"*"})
	actual := v1.deny_role_create_wildcard_verbs with input as in

	count(actual) == 1
}

input_create_cluster_role_more(user, verbs, role, api_groups, resources) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userInfo": {"username": user},
			"kind": {"kind": role, "group": "rbac.authorization.k8s.io", "version": "v1"},
			"operation": "CREATE",
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "monitoring-endpoints",
					"labels": {"rbac.example.com/aggregate-to-monitoring": "true"},
				},
				"rules": [{
					"apiGroups": api_groups,
					"resources": resources,
					"verbs": verbs,
				}],
			},
		},
	}
}

# All tests pass with policy-tester.
# There is one issue: the newly created network policy is not deleted and thus can not
# run several tests together since the following tests will report network already exists error.
# TODO: Enable k8s test after fixing bug in policy-tester.
test_resource_owner_good {
	in := input_network_policy("alice", "CREATE")

	p := {"approved_users": {"CREATE": {"alice", "bob"}}}
	actual := v1.whitelist_resource_owner_networkpolicy with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_deny_role_create_exec_pods_ok {
	in := input_create_cluster_role("bob", {"a", "b"}, {"pods/exec"}, "CONNECT")
	actual := v1.deny_role_create_exec_pods with input as in

	count(actual) == 0
}

test_resource_owner_good_no_params {
	in := input_network_policy("alice", "CREATE")

	actual := v1.whitelist_resource_owner_networkpolicy with input as in
	count(actual) == 0
}

test_deny_role_create_exec_pods_ok_no_exec_pods {
	in := input_create_cluster_role("bob", {"a", "create"}, {"no"}, "CONNECT")
	actual := v1.deny_role_create_exec_pods with input as in

	count(actual) == 0
}

test_resource_owner_bad_no_user {
	in := input_network_policy("alice", "CREATE")

	p := {"approved_users": {"CREATE": {"bob"}}}
	actual := v1.whitelist_resource_owner_networkpolicy with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_deny_role_create_exec_pods_fail {
	in := input_create_cluster_role("bob", {"*", "create"}, {"pods/exec"}, "CONNECT")
	actual := v1.deny_role_create_exec_pods with input as in

	count(actual) == 1
}

test_resource_owner_bad_no_operation {
	in := input_network_policy("alice", "CREATE")

	p := {"approved_users": {"DELETE": {"alice"}}}
	actual := v1.whitelist_resource_owner_networkpolicy with data.library.parameters as p
		with input as in

	count(actual) == 1
}

input_network_policy(user, operation) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userInfo": {"username": user},
			"operation": operation,
			"kind": {"kind": "NetworkPolicy"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "default",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": [
						"Ingress",
						"Egress",
					],
					"ingress": [{
						"from": [
							{"ipBlock": {
								"cidr": "172.17.0.0/16",
								"except": ["172.17.1.0/24"],
							}},
							{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
							{"podSelector": {"matchLabels": {"role": "frontend"}}},
						],
						"ports": [{
							"protocol": "TCP",
							"port": 6379,
						}],
					}],
					"egress": [{
						"to": [{"ipBlock": {"cidr": "10.0.0.0/24"}}],
						"ports": [{
							"protocol": "TCP",
							"port": 5978,
						}],
					}],
				},
			},
		},
	}
}

input_create_cluster_role(user, verbs, resources, op) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userInfo": {"username": user},
			"kind": {"kind": "ClusterRole", "group": "rbac.authorization.k8s.io", "version": "v1"},
			"operation": op,
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "monitoring-endpoints",
					"labels": {"rbac.example.com/aggregate-to-monitoring": "true"},
				},
				"rules": [
					{
						"apiGroups": [""],
						"resources": ["pods"],
						"verbs": ["get"],
					},
					{
						"apiGroups": [""],
						"resources": resources,
						"verbs": verbs,
					},
				],
			},
		},
	}
}

test_k8s_deny_clusterrole_create_wildcard_verbs_ok {
	in := input_create_cluster_role("bob", {"a", "b"}, {"pods/exec"}, "CREATE")
	actual := v1.deny_clusterrole_create_wildcard_verbs with input as in

	count(actual) == 0
}

test_k8s_deny_clusterrole_create_wildcard_verbs_fail {
	in := input_create_cluster_role("bob", {"*", "b"}, {"pods/exec"}, "CREATE")
	actual := v1.deny_clusterrole_create_wildcard_verbs with input as in

	count(actual) == 1
}

test_k8s_blacklist_namespace_serviceaccounts_no_parameter {
	in := input_create_service_account("alice", [])
	actual := v1.blacklist_namespace_serviceaccounts with input as in

	count(actual) == 0
}

test_k8s_blacklist_namespace_serviceaccounts_good {
	in := input_create_service_account("alice", [])
	p := {"prohibited_namespaces": {"ad*", "aaa"}}
	actual := v1.blacklist_namespace_serviceaccounts with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_blacklist_namespace_serviceaccounts_bad {
	in := input_create_service_account("alice", [])
	p := {"prohibited_namespaces": {"defppp", "aaa"}}
	actual := v1.blacklist_namespace_serviceaccounts with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_blacklist_namespace_serviceaccounts_service_account_good {
	in := input_create_service_account("system:serviceaccount:nstest:satest", ["system:serviceaccounts", "system:serviceaccounts:nstest"])

	p := {"prohibited_namespaces": {"defppp*", "aaa"}}
	actual := v1.blacklist_namespace_serviceaccounts with input as in
		with data.library.parameters as p

	count(actual) == 0
}

tets_deny_clusterrole_create_blacklist_userinfo_good {
	in := input_create_cluster_role("bob", {"a", "b"}, {"pods/exec"}, "CREATE")
	p := {"prohibited_users": {"alice", "dan"}}
	actual := v1.deny_clusterrole_create_blacklist_userinfo with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_deny_clusterrole_create_blacklist_userinfo_no_parameter {
	in := input_create_cluster_role("alice", {"a", "b"}, {"pods/exec"}, "CREATE")
	actual := v1.deny_clusterrole_create_blacklist_userinfo with input as in

	count(actual) == 0
}

test_deny_clusterrole_create_blacklist_userinfo_fail {
	in := input_create_cluster_role("alice", {"a", "b"}, {"pods/exec"}, "CREATE")
	p := {"prohibited_users": {"alice", "aaa"}}
	actual := v1.deny_clusterrole_create_blacklist_userinfo with input as in
		with data.library.parameters as p

	count(actual) == 1
}

tets_deny_clusterrole_create_whitelist_userinfo_fail {
	in := input_create_cluster_role("bob", {"a", "b"}, {"pods/exec"}, "CREATE")
	p := {"approved_users": {"alice", "dan"}}
	actual := v1.deny_clusterrole_create_non_whitelist_userinfo with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_deny_clusterrole_create_whitelist_userinfo_no_parameter {
	in := input_create_cluster_role("alice", {"a", "b"}, {"pods/exec"}, "CREATE")
	actual := v1.deny_clusterrole_create_non_whitelist_userinfo with input as in

	count(actual) == 0
}

test_deny_clusterrole_create_whitelist_userinfo_good {
	in := input_create_cluster_role("alice", {"a", "b"}, {"pods/exec"}, "CREATE")
	p := {"approved_users": {"alice", "aaa"}}
	actual := v1.deny_clusterrole_create_non_whitelist_userinfo with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_deny_clusterrolebinding_create_deny_subject_wildcard_bad {
	in := input_create_cluster_role_binding("*", "test")
	actual := v1.deny_clusterrolebinding_create_deny_subject_wildcard with input as in

	count(actual) == 1
}

test_k8s_deny_clusterrolebinding_create_deny_subject_wildcard_good {
	in := input_create_cluster_role_binding("bob", "test")
	actual := v1.deny_clusterrolebinding_create_deny_subject_wildcard with input as in

	count(actual) == 0
}

test_k8s_deny_clusterrolebinding_create_deny_subject_wildcard_fail_semantic {
	in := input_create_cluster_role_binding_semantic_all("test")
	actual := v1.deny_clusterrolebinding_create_deny_subject_wildcard with input as in

	count(actual) == 1
}

test_k8s_deny_clusterrolebinding_create_blacklist_rolename_no_parameter {
	in := input_create_cluster_role_binding("bob", "test")
	actual := v1.deny_clusterrolebinding_create_blacklist_rolename with input as in

	count(actual) == 0
}

test_k8s_deny_clusterrolebinding_create_blacklist_rolename_bad {
	in := input_create_cluster_role_binding("bob", "alice")
	p := {"prohibited_roles": {"alice", "aaa"}}
	actual := v1.deny_clusterrolebinding_create_blacklist_rolename with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_deny_clusterrolebinding_create_blacklist_rolename_good {
	in := input_create_cluster_role_binding("bob", "test")
	p := {"prohibited_roles": {"alice", "aaa"}}
	actual := v1.deny_clusterrolebinding_create_blacklist_rolename with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_deny_rolebinding_create_blacklist_clusterrolename_no_parameter {
	in := input_create_role_binding("bob", "ClusterRole", "test")
	actual := v1.deny_rolebinding_create_blacklist_rolename with input as in

	count(actual) == 0
}

test_k8s_deny_rolebinding_create_blacklist_clusterrolename_bad {
	in := input_create_role_binding("bob", "ClusterRole", "alice")
	p := {"prohibited_roles": {"alice", "aaa"}}
	actual := v1.deny_rolebinding_create_blacklist_rolename with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_deny_rolebinding_create_blacklist_clusterrolename_good {
	in := input_create_role_binding("bob", "ClusterRole", "test")
	p := {"prohibited_roles": {"alice", "aaa"}}
	actual := v1.deny_rolebinding_create_blacklist_rolename with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_deny_rolebinding_create_blacklist_rolename_no_parameter {
	in := input_create_role_binding("bob", "Role", "test")
	actual := v1.deny_rolebinding_create_blacklist_rolename with input as in

	count(actual) == 0
}

test_k8s_deny_rolebinding_create_blacklist_rolename_no_effect {
	in := input_create_role_binding("bob", "Role", "alice")
	p := {"prohibited_roles": {"alice", "aaa"}}
	actual := v1.deny_rolebinding_create_blacklist_rolename with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_deny_rolebinding_create_blacklist_rolename_good {
	in := input_create_role_binding("bob", "Role", "test")
	p := {"prohibited_roles": {"alice", "aaa"}}
	actual := v1.deny_rolebinding_create_blacklist_rolename with input as in
		with data.library.parameters as p

	count(actual) == 0
}

input_create_service_account(user, groups) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userInfo": {"username": user, "groups": groups},
			"kind": {"kind": "ServiceAccount"},
			"operation": "CREATE",
			"object": {
				"metadata": {
					"creationTimestamp": "2015-06-16T00:12:59.000Z",
					"name": "build-robot",
					"namespace": "defppp",
					"resourceVersion": "272500",
					"uid": "721ab723-13bc-11e5-aec2-42010af0021e",
				},
				"secrets": [{"name": "build-robot-token-bvbk5"}],
			},
		},
	}
}

input_create_role_binding(name, roleKind, roleName) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind": {"kind": "RoleBinding", "group": "rbac.authorization.k8s.io", "version": "v1"},
			"object": {
				"metadata": {"name": "read-secrets-global"},
				"subjects": [{
					"kind": "Group",
					"name": name,
					"apiGroup": "rbac.authorization.k8s.io",
				}],
				"roleRef": {
					"kind": roleKind,
					"name": roleName,
					"apiGroup": "rbac.authorization.k8s.io",
				},
			},
		},
	}
}

input_create_cluster_role_binding(name, roleName) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind": {"kind": "ClusterRoleBinding", "group": "rbac.authorization.k8s.io", "version": "v1"},
			"object": {
				"metadata": {"name": "read-secrets-global"},
				"subjects": [{
					"kind": "Group",
					"name": name,
					"apiGroup": "rbac.authorization.k8s.io",
				}],
				"roleRef": {
					"kind": "ClusterRole",
					"name": roleName,
					"apiGroup": "rbac.authorization.k8s.io",
				},
			},
		},
	}
}

input_create_cluster_role_binding_semantic_all(roleName) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind": {"kind": "ClusterRoleBinding", "group": "rbac.authorization.k8s.io", "version": "v1"},
			"object": {
				"metadata": {"name": "read-secrets-global"},
				"subjects": [
					{
						"kind": "Group",
						"name": "system:authenticated",
						"apiGroup": "rbac.authorization.k8s.io",
					},
					{
						"kind": "Group",
						"name": "system:unauthenticated",
						"apiGroup": "rbac.authorization.k8s.io",
					},
				],
				"roleRef": {
					"kind": "ClusterRole",
					"name": roleName,
					"apiGroup": "rbac.authorization.k8s.io",
				},
			},
		},
	}
}

test_k8s_deny_role_name_blacklist_prefix_ok_no_parameter {
	in := input_create_cluster_role_prefix("monitoring-endpoints", "bob", {"*", "b"}, "ClusterRole", {""}, {"*"})
	actual := v1.deny_role_name_blacklist_prefix with input as in

	count(actual) == 0
}

test_k8s_deny_role_name_blacklist_prefix_ok_parameter {
	in := input_create_cluster_role_prefix("monitoring-endpoints", "bob", {"*", "b"}, "ClusterRole", {""}, {"*"})
	p := {"prohibited_name_prefixes": {"system:"}}
	actual := v1.deny_role_name_blacklist_prefix with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_deny_role_name_blacklist_prefix_fail_parameter {
	in := input_create_cluster_role_prefix("system:monitoring-endpoints", "bob", {"*", "b"}, "ClusterRole", {""}, {"*"})
	p := {"prohibited_name_prefixes": {"system:"}}
	actual := v1.deny_role_name_blacklist_prefix with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_deny_cluster_role_binding_sensitive_roles_good {
	in := input_create_cluster_role_binding("alice", "non-sensitive")
	actual := v1.deny_cluster_role_binding_sensitive_roles with input as in

	count(actual) == 0
}

test_k8s_deny_cluster_role_binding_sensitive_roles_bad {
	in := input_create_cluster_role_binding("alice", "system:node")
	actual := v1.deny_cluster_role_binding_sensitive_roles with input as in

	count(actual) == 1
}

test_check_encryptionconfig_user_good {
	in := input_encryption_config("alice", {""})
	p := {"approved_users": {"alice", "dan"}}
	actual := v1.check_encryptionconfig_user with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_check_encryptionconfig_user_bad {
	in := input_encryption_config("bob", {"a"})
	p := {"approved_users": {"alice", "dan"}}
	actual := v1.check_encryptionconfig_user with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_check_encryptionconfig_user_no_parameter {
	in := input_encryption_config("bob", {""})
	actual := v1.check_encryptionconfig_user with input as in

	count(actual) == 0
}

test_check_encryptionconfig_group_good {
	in := input_encryption_config("alice", {"alice"})
	p := {"approved_groups": {"alice", "dan"}}
	actual := v1.check_encryptionconfig_group with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_check_encryptionconfig_group_bad {
	in := input_encryption_config("bob", {"bob"})
	p := {"approved_groups": {"alice", "dan"}}
	actual := v1.check_encryptionconfig_group with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_check_encryptionconfig_group_no_parameter {
	in := input_encryption_config("bob", {""})
	actual := v1.check_encryptionconfig_group with input as in

	count(actual) == 0
}

test_check_audit_sink_user_good {
	in := input_audit_sink_config("alice", {""})
	p := {"approved_users": {"alice", "dan"}}
	actual := v1.check_audit_sink_user with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_check_audit_sink_user_bad {
	in := input_audit_sink_config("bob", {""})
	p := {"approved_users": {"alice", "dan"}}
	actual := v1.check_audit_sink_user with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_check_audit_sink_user_no_parameter {
	in := input_audit_sink_config("bob", {""})
	actual := v1.check_audit_sink_user with input as in

	count(actual) == 0
}

test_check_audit_sink_group_good {
	in := input_audit_sink_config("alice", {"alice"})
	p := {"approved_groups": {"alice", "dan"}}
	actual := v1.check_audit_sink_group with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_check_audit_sink_group_bad {
	in := input_audit_sink_config("bob", {"charlie"})
	p := {"approved_groups": {"alice", "dan"}}
	actual := v1.check_audit_sink_group with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_check_audit_sink_group_no_parameter {
	in := input_audit_sink_config("bob", {""})
	actual := v1.check_audit_sink_group with input as in

	count(actual) == 0
}

input_audit_sink_config(user, group) = x {
	x = {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"userInfo": {"username": user, "groups": group},
			"kind": {"kind": "AuditSink"},
			"object": {
				"metadata": {"name": "mysink"},
				"spec": {
					"policy": {
						"level": "Metadata",
						"stages": ["ResponseComplete"],
					},
					"webhook": {
						"throttle": {
							"qps": 10,
							"burst": 15,
						},
						"clientConfig": {"url": "https://audit.app"},
					},
				},
			},
		},
	}
}

input_encryption_config(user, group) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"userInfo": {"username": user, "groups": group},
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["secrets"],
				"providers": [
					{"kms": {
						"name": "test",
						"endpoint": "c",
						"cachesize": 100,
						"timeout": "3s",
					}},
					{"identity": {}},
				],
			}]},
		},
	}
}

input_create_cluster_role_binding(name, roleName) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind": {"kind": "ClusterRoleBinding", "group": "rbac.authorization.k8s.io", "version": "v1"},
			"object": {
				"metadata": {"name": "read-secrets-global"},
				"subjects": [{
					"kind": "Group",
					"name": name,
					"apiGroup": "rbac.authorization.k8s.io",
				}],
				"roleRef": {
					"kind": "ClusterRole",
					"name": roleName,
					"apiGroup": "rbac.authorization.k8s.io",
				},
			},
		},
	}
}

input_create_cluster_role_prefix(name, user, verbs, role, api_groups, resources) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userInfo": {"username": user},
			"kind": {"kind": role, "group": "rbac.authorization.k8s.io", "version": "v1"},
			"operation": "CREATE",
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": name,
					"labels": {"rbac.example.com/aggregate-to-monitoring": "true"},
				},
				"rules": [{
					"apiGroups": api_groups,
					"resources": resources,
					"verbs": verbs,
				}],
			},
		},
	}
}

# allow_whitelist_roles_of_webhook_editors
test_k8s_allow_whitelist_roles_of_webhook_editors_bad1 {
	parameters := {"approved_roles": {"cluster-admin", "webhook-editor"}}
	verbs := {"create", "delete", "patch"}
	resources := {"*"}
	in := input_create_cluster_role_prefix("webhook-editor-1", "Alice", verbs, "ClusterRole", {""}, resources)
	actual := v1.allow_whitelist_roles_of_webhook_editors with input as in
		with data.library.parameters as parameters

	count(actual) == 1
}

test_k8s_allow_whitelist_roles_of_webhook_editors_bad2 {
	parameters := {"approved_roles": {"cluster-admin", "webhook-editor"}}
	verbs := {"create", "delete", "patch"}
	resources := {"ValidatingWebhookConfigurations", "MutatingWebhookConfigurations"}
	in := input_create_cluster_role_prefix("webhook-editor-1", "Alice", verbs, "ClusterRole", {""}, resources)
	actual := v1.allow_whitelist_roles_of_webhook_editors with input as in
		with data.library.parameters as parameters

	count(actual) == 1
}

test_k8s_allow_whitelist_roles_of_webhook_editors_bad3 {
	parameters := {"approved_roles": {"cluster-admin", "webhook-editor"}}
	verbs := {"create", "delete", "patch"}
	resources := {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}
	in := input_create_cluster_role_prefix("webhook-editor-1", "Alice", verbs, "ClusterRole", {""}, resources)
	actual := v1.allow_whitelist_roles_of_webhook_editors with input as in
		with data.library.parameters as parameters

	count(actual) == 1
}

test_k8s_allow_whitelist_roles_of_webhook_editors_good {
	parameters := {"approved_roles": {"cluster-admin", "webhook-editor"}}
	verbs := {"create", "delete", "patch"}
	resources := {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}
	in := input_create_cluster_role_prefix("webhook-editor", "Alice", verbs, "ClusterRole", {""}, resources)
	actual := v1.allow_whitelist_roles_of_webhook_editors with input as in
		with data.library.parameters as parameters

	count(actual) == 0
}
