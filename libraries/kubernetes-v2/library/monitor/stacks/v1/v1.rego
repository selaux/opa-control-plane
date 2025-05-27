package library.v1.kubernetes.monitor.stacks.v1

import data.library.v1.kubernetes.utils.v1 as utils

import data.context.policy
import data.context.resources
import data.context.stack_id

# stack rules

monitoring_failure[[resource, errormsg]] {
	not resources.namespaces[namespace].metadata.labels["openpolicyagent.org/webhook"] == "ignore"
	resource := resources.namespace[namespace][name]
	resource.metadata.name = name
	params := {
		"pluralkind": "namespaces",
		"name": name,
		"namespace": namespace,
		"operation": "CREATE",
		"username": "alice",
	}

	wrapped := utils.admission_with_namespace(resource, params)
	data.stacks[stack_id][policy].enforce[decision] with input as wrapped
	errormsg := utils.get_decision_message(decision)
}

monitoring_failure[[resource, errormsg]] {
	not resources.namespaces[namespace].metadata.labels["openpolicyagent.org/webhook"] == "ignore"
	resource := resources.namespaces[namespace][name]
	resource.metadata.name = name
	params := {
		"pluralkind": "namespaces",
		"name": name,
		"namespace": namespace,
		"operation": "CREATE",
		"username": "alice",
	}

	wrapped := utils.admission_with_namespace(resource, params)
	data.stacks[stack_id][policy].monitor[decision] with input as wrapped
	errormsg := utils.get_decision_message(decision)
}

monitoring_failure[[resource, errormsg]] {
	not kind == "namespaces"
	resource := resources[kind][name]
	resource.metadata.name = name
	params := {
		"pluralkind": kind,
		"name": name,
		"operation": "CREATE",
		"username": "alice",
	}

	wrapped := utils.admission_no_namespace(resource, params)
	data.stacks[stack_id][policy].enforce[decision] with input as wrapped
	errormsg := utils.get_decision_message(decision)
}

monitoring_failure[[resource, errormsg]] {
	not kind == "namespaces"
	resource := resources[kind][name]
	resource.metadata.name = name
	params := {
		"pluralkind": kind,
		"name": name,
		"operation": "CREATE",
		"username": "alice",
	}

	wrapped := utils.admission_no_namespace(resource, params)
	data.stacks[stack_id][policy].monitor[decision] with input as wrapped
	errormsg := utils.get_decision_message(decision)
}
