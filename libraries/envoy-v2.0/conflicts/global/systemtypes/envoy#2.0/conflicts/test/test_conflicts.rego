package conflicts.test

import data.global.systemtypes["envoy:2.0"].conflicts.entry

# Note: double-brace indicates to the templating engine a template variable.
#  So in Rego replace double-brace  with { {
#  We cannot write a double-brace even in a comment, hence the use of "double-brace"
test_system_allow_egress {
	system := {"egress": {"allow": true, "headers": {"foo": "bar"}}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with input as input_request

	ans.allowed == true
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.headers.foo == "bar"
	ans.outcome.http_status == 200
	ans.outcome.policy_type == "egress"
	ans.outcome.stacks == {}
}

test_system_allow_ingress {
	system := {"ingress": {"allow": true, "headers": {"foo": "bar"}, "status_code": 201}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "ingress"}}}}}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with input as input_request

	ans.allowed == true
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.headers.foo == "bar"
	ans.outcome.http_status == 201
	ans.outcome.policy_type == "ingress"
	ans.outcome.stacks == {}
}

test_stack_egress {
	applicable_stacks := {"stack1"}
	stack1 := {"egress": {"deny": true}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with input as input_request

	ans.allowed == false
	ans.headers["x-ext-auth-allow"] == "no"
	ans.outcome.http_status == 403
	ans.outcome.policy_type == "egress"
	ans.outcome.decision_type == "DENIED"
	count(ans.outcome.stacks.stack1.denied) == 1
	count(ans.outcome.stacks.stack1.allowed) == 0
	ans.outcome.stacks.stack1.denied[_] == true
}

test_stack_ingress {
	applicable_stacks := {"stack1"}
	stack1 := {"ingress": {"allow": true}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "ingress"}}}}}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with input as input_request

	ans.allowed == true
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.outcome.http_status == 200
	ans.outcome.policy_type == "ingress"
	ans.outcome.decision_type == "ALLOWED"
	count(ans.outcome.stacks.stack1.denied) == 0
	count(ans.outcome.stacks.stack1.allowed) == 1
	ans.outcome.stacks.stack1.allowed[_] == true
}

test_stack_ingress_allow_Deny {
	applicable_stacks := {"stack1"}
	stack1 := {"ingress": {"allow": true, "deny": true}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "ingress"}}}}}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with input as input_request

	ans.allowed == false
	ans.headers["x-ext-auth-allow"] == "no"
	ans.outcome.http_status == 403
	ans.outcome.policy_type == "ingress"
	ans.outcome.decision_type == "DENIED"
	count(ans.outcome.stacks.stack1.denied) == 1
	count(ans.outcome.stacks.stack1.allowed) == 1
	ans.outcome.stacks.stack1.denied[_] == true
	ans.outcome.stacks.stack1.allowed[_] == true
}

test_stack_precedence_over_ingress {
	applicable_stacks := {"stack1"}
	stack1 := {"ingress": {"allow": true}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "ingress"}}}}}

	system := {"ingress": {"deny": true}}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with input as input_request
		with data.policy as system

	ans.allowed == true
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.outcome.http_status == 200
	ans.outcome.policy_type == "ingress"
	ans.outcome.decision_type == "ALLOWED"
	count(ans.outcome.stacks.stack1.denied) == 0
	count(ans.outcome.stacks.stack1.allowed) == 1
	ans.outcome.stacks.stack1.allowed[_] == true
}

test_stack_precedence_over_egress {
	applicable_stacks := {"stack1"}
	stack1 := {"egress": {"allow": true}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	system := {"egress": {"deny": true}}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with input as input_request
		with data.policy as system

	ans.allowed == true
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.outcome.http_status == 200
	ans.outcome.policy_type == "egress"
	ans.outcome.decision_type == "ALLOWED"
	count(ans.outcome.stacks.stack1.denied) == 0
	count(ans.outcome.stacks.stack1.allowed) == 1
	ans.outcome.stacks.stack1.allowed[_] == true
}

test_no_system_no_stacks {
	applicable_stacks := {"stack1"}
	stack1 := {"egress": {}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	system := {"egress": {}}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with input as input_request
		with data.policy as system

	ans.allowed == false
	ans.headers["x-ext-auth-allow"] == "no"
	ans.outcome.http_status == 403
	ans.outcome.policy_type == "egress"
	ans.outcome.decision_type == "DENIED"
}
