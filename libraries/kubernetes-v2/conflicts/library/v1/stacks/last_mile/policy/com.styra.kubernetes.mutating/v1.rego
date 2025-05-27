package library.v1.stacks.last_mile.policy["com.styra.kubernetes.mutating"].v1

import data.library.v1.stacks.resolutions.preemptive.allow_then_deny.v1 as allow_then_deny
import data.library.v1.utils.json.v1 as util_json
import data.library.v1.utils.object.v1 as util_object

# {
#   "apiVersion": "admission.k8s.io/v1",
#   "kind": "AdmissionReview",
#   "response": {
#     "uid": "<value from request.uid>",
#     "allowed": true,
#     "patchType": "JSONPatch",
#     "patch": "W3sib3AiOiAiYWRkIiwgInBhdGgiOiAiL3NwZWMvcmVwbGljYXMiLCAidmFsdWUiOiAzfV0="
#   }
# }

outcome = x {
	x := allow_then_deny.main with data.context.options as {"allowed": true} # Fail open.
}

code = x {
	outcome.allowed == false
	x := 403
}

else = x {
	x := 200
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

status = x {
	x := {
		"code": code,
		"message": outcome.message,
	}
}

status = x {
	not outcome.message
	x := {"code": code}
}

# stack patches take precedence hence they are appended to the end of the patch array
patch := util_json.ensure_parent_paths_exist(array.concat(system_patch, stack_patch))

stack_patch := [p | outcome.stacks[_].enforced[decision]; p := decision.patch[_]]

system_patch = [p | outcome.system.enforced[decision]; p := decision.patch[_]]

decision_type = x {
	outcome.allowed
	requires_patching
	x := "ADVICE"
}

decision_type = x {
	outcome.allowed
	not requires_patching
	x := "ALLOWED"
}

decision_type = x {
	not outcome.allowed
	x := "DENIED"
}

outcome_with_decision_type = object.union(outcome, {"decision_type": decision_type})

main = x {
	requires_patching
	x := {
		"apiVersion": apiVersion,
		"kind": "AdmissionReview",
		"outcome": outcome_with_decision_type,
		"response": {
			"uid": response_uid,
			"allowed": outcome.allowed,
			"patchJSON": patch,
			"patchType": "JSONPatch",
			"patch": base64.encode(json.marshal(patch)),
			"status": status,
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
			"status": status,
		},
	}
}

requires_patching {
	count(patch) != 0
}
