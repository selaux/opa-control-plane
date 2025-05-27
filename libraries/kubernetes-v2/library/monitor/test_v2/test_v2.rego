package library.v1.kubernetes.monitor.test_v2

import data.library.v1.kubernetes.monitor.v2 as monitor

mock_resource(name, kind) = obj {
	obj := {
		"kind": kind,
		"metadata": {"name": name},
	}
}

resources := {
	"clusterrolebindings": {"cluster-role": mock_resource("cluster-role", "ClusterRoleBinding")},
	"pods": {"the-ns": {"peas": mock_resource("peas", "Pod")}},
	"services": {
		"marvel": {"jarvis": mock_resource("jarvis", "Service")},
		"dc": {"alfred": mock_resource("alfred", "Service")},
	},
}

test_namespaced_objects {
	objs := monitor.namespaced_objects with data.kubernetes.resources as resources

	objs == {
		[
			mock_resource("peas", "Pod"),
			{
				"name": "peas",
				"namespace": "the-ns",
				"operation": "CREATE",
				"pluralkind": "pods",
				"kind": "Pod",
				"username": "alice",
			},
		],
		[
			mock_resource("jarvis", "Service"),
			{
				"name": "jarvis",
				"namespace": "marvel",
				"operation": "CREATE",
				"pluralkind": "services",
				"kind": "Service",
				"username": "alice",
			},
		],
		[
			mock_resource("alfred", "Service"),
			{
				"name": "alfred",
				"namespace": "dc",
				"operation": "CREATE",
				"pluralkind": "services",
				"kind": "Service",
				"username": "alice",
			},
		],
	}
}

test_global_objects {
	objs := monitor.global_objects with data.kubernetes.resources as resources

	objs == {[
		mock_resource("cluster-role", "ClusterRoleBinding"),
		{
			"name": "cluster-role",
			"operation": "CREATE",
			"pluralkind": "clusterrolebindings",
			"kind": "ClusterRoleBinding",
			"username": "alice",
		},
	]}
}

all_objects := {
	mock_resource("cluster-role", "ClusterRoleBinding"),
	mock_resource("peas", "Pod"),
	mock_resource("jarvis", "Service"),
	mock_resource("alfred", "Service"),
}

test_monitoring_failure_no_stack {
	outcome := monitor.monitoring_failure with data.context.policy_type as "validating"
		with data.context.system_id as "sys_id"
		with data.context.system_type as "kubernetes"
		with data.kubernetes.resources as resources
		with data.policy["com.styra.kubernetes.validating"].rules.rules.enforce as {{"allowed": false, "message": "enforce"}}
		with data.policy["com.styra.kubernetes.validating"].rules.rules.monitor as {{"allowed": false, "message": "monitor"}}

	messages := {"enforce", "monitor"}

	expected := {[obj, msg] | all_objects[obj]; messages[msg]}

	outcome == expected
}

test_monitoring_failure_with_a_stack {
	outcome := monitor.monitoring_failure with data.context.policy_type as "validating"
		with data.context.system_id as "sys_id"
		with data.context.system_type as "kubernetes"
		with data.policy["com.styra.kubernetes.validating"].rules.rules.enforce as {{"allowed": false, "message": "enforce"}}
		with data.policy["com.styra.kubernetes.validating"].rules.rules.monitor as {{"allowed": false, "message": "monitor"}}
		with data.stacks as {"stack_id": {"selectors": {"systems": {"sys_id"}}}}
		with data.stacks.stack_id.policy["com.styra.kubernetes.validating"].rules.rules.enforce as {{"allowed": false, "message": "stack enforce"}}
		with data.stacks.stack_id.policy["com.styra.kubernetes.validating"].rules.rules.monitor as {{"allowed": false, "message": "stack monitor"}}
		with data.styra.systems as [{"id": "sys_id", "type": "kubernetes"}]
		with data.styra.stacks as {"stack_id": {"config": {"type": "kubernetes"}}}
		with data.kubernetes.resources as resources

	messages := {"stack enforce", "stack monitor", "enforce", "monitor"}

	expected := {[obj, msg] | messages[msg]; all_objects[obj]}

	outcome == expected
}

legacy_monitoring_failure_with_a_stack = outcome {
	outcome := monitor.monitoring_failure with data.context.policy_type as "validating"
		with data.context.system_id as "sys_id"
		with data.context.system_type as "kubernetes"
		with data.policy["com.styra.kubernetes.validating"].rules.rules.deny as {{"allowed": false, "message": "deny"}, legacy_message("deny")}
		with data.policy["com.styra.kubernetes.validating"].rules.rules.enforce as {legacy_message("enforce")}
		with data.policy["com.styra.kubernetes.validating"].rules.rules.monitor as {legacy_message("monitor")}
		with data.stacks as {"stack_id": {"selectors": {"systems": {"sys_id"}}}}
		with data.stacks.stack_id.policy["com.styra.kubernetes.validating"].rules.rules.deny as {{"allowed": false, "message": "stack deny"}, legacy_message("stack deny")}
		with data.stacks.stack_id.policy["com.styra.kubernetes.validating"].rules.rules.enforce as {legacy_message("stack enforce")}
		with data.stacks.stack_id.policy["com.styra.kubernetes.validating"].rules.rules.monitor as {legacy_message("stack monitor")}
		with data.styra.systems as [{"id": "sys_id", "type": "kubernetes"}]
		with data.styra.stacks as {"stack_id": {"config": {"type": "kubernetes"}}}
		with data.kubernetes.resources as resources

	messages := {"stack deny", "deny", legacy_message("deny"), legacy_message("enforce"), legacy_message("monitor"), legacy_message("stack deny"), legacy_message("stack enforce"), legacy_message("stack monitor")}
}

# expected := {[obj, msg] | messages[msg]; all_objects[obj]}

# outcome == expected

legacy_message(mode) = s {
	s := sprintf("legacy string - %s", [mode])
}
