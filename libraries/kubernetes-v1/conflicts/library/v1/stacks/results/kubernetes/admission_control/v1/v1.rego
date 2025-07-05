package library.v1.stacks.results.kubernetes.admission_control.v1

import data.library.v1.stacks.resolutions.preemptive.allow_then_deny.v1 as allow_then_deny

outcome = x {
	x := allow_then_deny.main with data.context.options as {"allowed": true} # Fail open.
}

decision_type = x {
	outcome.allowed
	x := "ALLOWED"
}

decision_type = x {
	not outcome.allowed
	x := "DENIED"
}

outcome_with_decision_type := object.union(outcome, {"decision_type": decision_type})

code = x {
	outcome.allowed == false
	x := 403
}

apiVersion = x {
	x := input.apiVersion
}

else = x {
	x := "admission.k8s.io/v1beta1"
}

response_uid = x {
	x := input.request.uid
}

else = x {
	x := "" # missing uid is set to empty string
}

main = x {
	x := {
		"apiVersion": apiVersion,
		"kind": "AdmissionReview",
		"outcome": outcome_with_decision_type,
		"response": {
			"uid": response_uid,
			"allowed": outcome.allowed,
			"status": {
				"code": code,
				"message": outcome.message,
			},
		},
	}
}

else = x {
	x := {
		"apiVersion": apiVersion,
		"kind": "AdmissionReview",
		"outcome": outcome_with_decision_type,
		"response": {
			"uid": response_uid,
			"allowed": outcome.allowed,
			"status": {"message": outcome.message},
		},
	}
}

else = x {
	x := {
		"apiVersion": apiVersion,
		"kind": "AdmissionReview",
		"outcome": outcome_with_decision_type,
		"response": {
			"uid": response_uid,
			"allowed": outcome.allowed,
			"status": {"code": code},
		},
	}
}

else = x {
	x := {
		"apiVersion": apiVersion,
		"kind": "AdmissionReview",
		"outcome": outcome_with_decision_type,
		"response": {
			"uid": response_uid,
			"allowed": outcome.allowed,
		},
	}
}
