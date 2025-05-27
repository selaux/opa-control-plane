package library.v1.kubernetes.monitor.test_v1

import data.library.v1.kubernetes.monitor.v1

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
		"the-ns": {"igor": mock_resource("igor", "Service")},
		"second-ns": {"goblin": mock_resource("goblin", "Service")},
	},
}

test_namespace_objects {
	objs := v1.objects_with_a_namespace with data.kubernetes.resources as resources

	objs == {
		[
			mock_resource("peas", "Pod"),
			{
				"name": "peas",
				"namespace": "the-ns",
				"operation": "CREATE",
				"pluralkind": "pods",
				"username": "alice",
			},
		],
		[
			mock_resource("igor", "Service"),
			{
				"name": "igor",
				"namespace": "the-ns",
				"operation": "CREATE",
				"pluralkind": "services",
				"username": "alice",
			},
		],
		[
			mock_resource("goblin", "Service"),
			{
				"name": "goblin",
				"namespace": "second-ns",
				"operation": "CREATE",
				"pluralkind": "services",
				"username": "alice",
			},
		],
	}
}

test_global_objects {
	objs := v1.global_objects with data.kubernetes.resources as resources

	objs == {[
		mock_resource("cluster-role", "ClusterRoleBinding"),
		{
			"name": "cluster-role",
			"operation": "CREATE",
			"pluralkind": "clusterrolebindings",
			"username": "alice",
		},
	]}
}

all_objects := {
	mock_resource("cluster-role", "ClusterRoleBinding"),
	mock_resource("peas", "Pod"),
	mock_resource("igor", "Service"),
	mock_resource("goblin", "Service"),
}

test_monitoring_failure_no_stack {
	outcome := v1.monitoring_failure with data.context.system_id as "sys_id"
		with data.context.policy as "admission_control"
		with data.kubernetes.resources as resources
		with data.admission_control.enforce as {{"message": "enforce"}, "enforce string"}
		with data.admission_control.deny as {"deny"}
		with data.admission_control.monitor as {{"message": "monitor"}, "monitor string"}

	messages := {"enforce", "enforce string", "deny", "monitor", "monitor string"}

	expected := {[obj, msg] | messages[msg]; all_objects[obj]}

	outcome == expected
}

test_monitoring_failure_with_a_stack {
	outcome := v1.monitoring_failure with data.context.system_id as "sys_id"
		with data.context.policy as "admission_control"
		with data.kubernetes.resources as resources
		with data.styra.systems as [{"id": "sys_id", "type": "kubernetes"}]
		with data.styra.stacks as {"stack_id": {"config": {"type": "kubernetes"}}}
		with data.stacks as {"stack_id": {"selectors": {"systems": {"sys_id"}}}}
		with data.stacks.stack_id.admission_control.enforce as {{"message": "stack enforce"}}
		with data.stacks.stack_id.admission_control.monitor as {{"message": "stack monitor"}}
		with data.admission_control.enforce as {{"message": "enforce"}, "enforce string"}
		with data.admission_control.deny as {"deny"}
		with data.admission_control.monitor as {{"message": "monitor"}, "monitor string"}

	messages := {"stack enforce", "stack monitor", "enforce", "enforce string", "deny", "monitor", "monitor string"}

	expected := {[obj, msg] | messages[msg]; all_objects[obj]}

	outcome == expected
}
