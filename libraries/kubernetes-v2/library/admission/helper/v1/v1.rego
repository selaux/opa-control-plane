package library.v1.kubernetes.admission.helper.v1

import data.library.v1.kubernetes.utils.v1 as utils

# -----------------------------------------------------------------------
# Helper rule to construct the expected k8s admission controller response

admission_control_response = {
	"apiVersion": "admission.k8s.io/v1beta1",
	"kind": "AdmissionReview",
	"response": response,
}

default response = {"allowed": true}

response = x {
	x := {
		"allowed": false,
		"status": {"reason": reason},
	}

	reason = concat(", ", data.admission_control.deny)

	reason != ""
}

else = x {
	x := {
		"allowed": true,
		"status": {"reason": reason},
	}

	reason = concat(", ", get_monitor_message(data.admission_control.monitor))

	reason != ""
}

get_monitor_message(monitor) = message {
	is_string(monitor)
	message := monitor
}

get_monitor_message(monitor) = message {
	not is_string(monitor)
	message := monitor.message
}

# ----------------------------------------------------------------------
# Helper for the monitoring rule, expects resources and admissioncontrol
# This is deprecated and will be removed after the transition to stacks

monitoring_failure[[resource, errormsg]] {
	not data.kubernetes.resources.namespaces[namespace].metadata.labels["openpolicyagent.org/webhook"] == "ignore"
	resource := data.kubernetes.resources[kind][namespace][name]
	resource.metadata.name = name
	params := {
		"pluralkind": kind,
		"name": name,
		"namespace": namespace,
		"operation": "CREATE",
		"username": "alice",
	}

	wrapped := utils.admission_with_namespace(resource, params)
	data.admission_control.deny[errormsg] with input as wrapped
}

monitoring_failure[[resource, errormsg]] {
	not data.kubernetes.resources.namespaces[namespace].metadata.labels["openpolicyagent.org/webhook"] == "ignore"
	resource := data.kubernetes.resources[kind][namespace][name]
	resource.metadata.name = name
	params := {
		"pluralkind": kind,
		"name": name,
		"namespace": namespace,
		"operation": "CREATE",
		"username": "alice",
	}

	wrapped := utils.admission_with_namespace(resource, params)
	data.admission_control.monitor[errormsg] with input as wrapped
}

monitoring_failure[[resource, errormsg]] {
	resource := data.kubernetes.resources[kind][name]
	resource.metadata.name = name
	params := {
		"pluralkind": kind,
		"name": name,
		"operation": "CREATE",
		"username": "alice",
	}

	wrapped := utils.admission_no_namespace(resource, params)
	data.admission_control.deny[errormsg] with input as wrapped
}

monitoring_failure[[resource, errormsg]] {
	resource := data.kubernetes.resources[kind][name]
	resource.metadata.name = name
	params := {
		"pluralkind": kind,
		"name": name,
		"operation": "CREATE",
		"username": "alice",
	}

	wrapped := utils.admission_no_namespace(resource, params)
	data.admission_control.monitor[errormsg] with input as wrapped
}
