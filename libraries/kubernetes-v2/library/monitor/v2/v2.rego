package library.v1.kubernetes.monitor.v2

import data.library.v1.kubernetes.utils.v1 as utils

import data.context.policy_type
import data.context.system_id
import data.context.system_type

# this policy is invoked by a kubernetes system's monitor policy
#
# import data.library.v1.kubernetes.monitor.v2 as monitor
#
# monitoring_failure[[resource, errormsg]] {
# 	monitor.monitoring_failure[[resource, errormsg]] with data.context as {
# 		"policy_type": "validating", # or "mutating"
# 		"system_id": "<system-id>",
# 		"system_type": "kubernetes",
# 	}
# }

monitoring_failure[[resource, errormsg]] {
	namespaced_objects[[resource, params]]
	wrapped := utils.admission_with_namespace(resource, params)
	outcome := data.library.v1.stacks.decision.v2.main_monitoring with input as wrapped

	errormsg := outcome.messages[_]
}

monitoring_failure[[resource, errormsg]] {
	global_objects[[resource, params]]
	wrapped := utils.admission_no_namespace(resource, params)
	outcome := data.library.v1.stacks.decision.v2.main_monitoring with input as wrapped

	errormsg := outcome.messages[_]
}

# namespaced_objects are all kubernetes resources within namespaces
namespaced_objects[[resource, params]] {
	resources := data.kubernetes.resources
	not resources.namespaces[namespace].metadata.labels["openpolicyagent.org/webhook"] == "ignore"
	resource := resources[kind][namespace][name]
	resource.metadata.name = name
	params := {
		"kind": resource.kind,
		"pluralkind": kind,
		"name": name,
		"namespace": namespace,
		"operation": "CREATE",
		"username": "alice",
	}
}

# namespaced_objects are all kubernetes resources within namespaces
namespaced_objects_kind[[kind, resource, params]] {
	resources := data.kubernetes.resources
	not resources.namespaces[namespace].metadata.labels["openpolicyagent.org/webhook"] == "ignore"
	resource := resources[kind][namespace][name]
	resource.metadata.name = name
	params := {
		"kind": resource.kind,
		"pluralkind": kind,
		"name": name,
		"namespace": namespace,
		"operation": "CREATE",
		"username": "alice",
	}
}

# global_objects are kubernetes objects that are not associated with a namespace
global_objects[[resource, params]] {
	resources := data.kubernetes.resources
	resource := resources[kind][name]

	# name above will select the namespace name for namespaced objects. Below ensures that name is actually the
	# object's name so that namespaced objects are filtered out
	resource.metadata.name = name
	params := {
		"kind": resource.kind,
		"pluralkind": kind,
		"name": name,
		"operation": "CREATE",
		"username": "alice",
	}
}
