package conflicts.test

import data.TYPELIB.conflicts.entry

# Note: double-brace indicates to the templating engine a template variable.
#  So in Rego replace double-brace  with { {
#  We cannot write a double-brace even in a comment, hence the use of "double-brace"
test_system_allow_egress {
	system := {"egress": {"allow": true, "headers": {"foo": "bar"}}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with input as input_request
		with data.self.metadata.system_type as "envoy"

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
		with data.self.metadata.system_type as "envoy"

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
		with data.self.metadata.system_type as "envoy"

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
		with data.self.metadata.system_type as "envoy"

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
		with data.self.metadata.system_type as "envoy"

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
		with data.self.metadata.system_type as "envoy"

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
		with data.self.metadata.system_type as "envoy"

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
		with data.self.metadata.system_type as "envoy"

	ans.allowed == false
	ans.headers["x-ext-auth-allow"] == "no"
	ans.outcome.http_status == 403
	ans.outcome.policy_type == "egress"
	ans.outcome.decision_type == "DENIED"
}

test_system_ingress_body {
	applicable_stacks := {"stack1"}
	stack1 := {"ingress": {}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "ingress"}}}}}

	system := {"ingress": {"allow": true, "body": "body message"}}

	ans := entry.main with input as input_request
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.policy as system
		with data.self.metadata.system_type as "envoy"

	ans.allowed == true
	ans.code == 200
	ans.http_status == 200
	ans.body == "body message"
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.outcome.policy_type == "ingress"
	ans.outcome.decision_type == "ALLOWED"
}

test_stack_ingress_body {
	applicable_stacks := {"stack1"}
	stack1 := {"ingress": {"allow": true, "body": "stack body message"}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "ingress"}}}}}

	system := {"ingress": {"deny": true, "body": "system body message"}}

	ans := entry.main with input as input_request
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.policy as system
		with data.self.metadata.system_type as "envoy"

	ans.allowed == true
	ans.code == 200
	ans.http_status == 200
	ans.body == "stack body message"
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.outcome.policy_type == "ingress"
	ans.outcome.decision_type == "ALLOWED"
}

test_system_egress_body {
	applicable_stacks := {"stack1"}
	stack1 := {"egress": {}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	system := {"egress": {"allow": true, "body": "body message"}}

	ans := entry.main with input as input_request
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.policy as system
		with data.self.metadata.system_type as "envoy"

	ans.allowed == true
	ans.code == 200
	ans.http_status == 200
	ans.body == "body message"
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.outcome.policy_type == "egress"
	ans.outcome.decision_type == "ALLOWED"
}

test_stack_egress_body {
	applicable_stacks := {"stack1"}
	stack1 := {"egress": {"allow": true, "body": "stack body message"}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	system := {"egress": {"deny": true, "body": "system body message"}}

	ans := entry.main with input as input_request
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.policy as system
		with data.self.metadata.system_type as "envoy"

	ans.allowed == true
	ans.code == 200
	ans.http_status == 200
	ans.body == "stack body message"
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.outcome.policy_type == "egress"
	ans.outcome.decision_type == "ALLOWED"
}

test_stack_header_conflict {
	applicable_stacks := {"stack1", "stack2"}
	stack1 := {"egress": {"allow": true, "headers": {"foo": "bar"}}}
	stack2 := {"egress": {"allow": true, "headers": {"foo": "qux"}}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	system := {"egress": {}}

	ans := entry.main with input as input_request
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.stacks.stack2.policy as stack2
		with data.policy as system
		with data.self.metadata.system_type as "envoy"

	ans.allowed == true
	ans.code == 200
	ans.http_status == 200
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.headers.foo = _ # doesn't matter which value -- but there must be one
	ans.outcome.policy_type == "egress"
	ans.outcome.decision_type == "ALLOWED"
}

test_stack_header_extauth {
	applicable_stacks := {"stack1"}
	stack1 := {"egress": {"allow": true, "headers": {"x-ext-auth-allow": "whatever"}}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	system := {"egress": {}}

	ans := entry.main with input as input_request
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.policy as system
		with data.self.metadata.system_type as "envoy"

	ans.allowed == true
	ans.code == 200
	ans.http_status == 200

	# not ideal, but better than a rego conflict error
	ans.headers["x-ext-auth-allow"] == "whatever"
	ans.outcome.policy_type == "egress"
	ans.outcome.decision_type == "ALLOWED"
}

test_stack_multi_priority {
	applicable_stacks := {"stack1", "stack2", "stack3"}
	stack1 := {"egress": {"allow": true, "status_code": 403, "priority": 2, "custom": "stack1"}}
	stack2 := {"egress": {"allow": true, "status_code": 200, "priority": 3, "custom": "stack2"}}
	stack3 := {"egress": {"allow": true, "status_code": 401, "priority": 1, "custom": "stack3"}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	system := {"egress": {}}

	ans := entry.main with input as input_request
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.stacks.stack2.policy as stack2
		with data.stacks.stack3.policy as stack3
		with data.policy as system
		with data.self.metadata.system_type as "envoy"

	ans.allowed == true
	ans.code == 401
	ans.custom == "stack3"
}

test_stack_deny_over_allow {
	applicable_stacks := {"stack1", "stack2"}
	stack1 := {"egress": {"deny": true, "status_code": 403, "priority": 1, "custom": "stack1"}}
	stack2 := {"egress": {"allow": true, "status_code": 200, "priority": 2, "custom": "stack2"}}
	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "egress"}}}}}

	system := {"egress": {}}

	ans := entry.main with input as input_request
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.stacks.stack2.policy as stack2
		with data.policy as system
		with data.self.metadata.system_type as "envoy"

	ans.allowed == false
	ans.code == 403
	ans.custom == "stack1"
}

test_system_all_fields {
	system := {"ingress": {
		"allow": true,
		"headers": {"foo": "bar"},
		"status_code": 201,
		"body": "whatever",
		"response_headers_to_add": {"x-foo": "bar"},
		"request_headers_to_remove": ["one-auth-header", "another-auth-header"],
		"custom": ["a great string to be sure"],
	}}

	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "ingress"}}}}}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with input as input_request
		with data.self.metadata.system_type as "envoy"

	ans.allowed == true
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.headers.foo == "bar"
	ans.code == 201
	ans.body == "whatever"
	ans.response_headers_to_add == {"x-foo": "bar"}
	ans.request_headers_to_remove == ["one-auth-header", "another-auth-header"]
	ans.custom == ["a great string to be sure"]
	ans.outcome.policy_type == "ingress"
	ans.outcome.stacks == {}
}

test_stack_all_fields {
	applicable_stacks := {"stack1"}
	system := {"ingress": {
		"allow": true,
		"headers": {"foo": "bar"},
		"status_code": 201,
		"body": "whatever",
		"response_headers_to_add": {"x-foo": "bar"},
		"request_headers_to_remove": ["one-auth-header", "another-auth-header"],
		"custom": ["a great string to be sure"],
	}}

	stack1 := {"ingress": {
		"deny": true,
		"headers": {"foo": "bar2"},
		"status_code": 403,
		"body": "whatever 2",
		"response_headers_to_add": {"x-foo": "bar2"},
		"request_headers_to_remove": ["one-auth-header", "another-auth-header2"],
		"custom": ["another great string"],
	}}

	input_request := {"attributes": {"metadataContext": {"filterMetadata": {"envoy.filters.http.header_to_metadata": {"policy_type": "ingress"}}}}}

	ans := entry.main with data.policy as system
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with input as input_request
		with data.self.metadata.system_type as "envoy"

	ans.allowed == false
	ans.headers["x-ext-auth-allow"] == "no"
	ans.headers.foo == "bar2"
	ans.code == 403
	ans.body == "whatever 2"
	ans.response_headers_to_add == {"x-foo": "bar2"}
	ans.request_headers_to_remove == ["one-auth-header", "another-auth-header2"]
	ans.custom == ["another great string"]
	ans.outcome.policy_type == "ingress"
}

test_applicable_stacks {
	stack_metadata := {
		"stack1": {"config": {"type": "template.envoy:2.0"}},
		"stack2": {"config": {"type": "template.envoy:2.1"}},
		"stack3": {"config": {"type": "template.envoy:3.1"}},
		"stack4": {"config": {"type": "template.foobar:2.0"}},
	}

	self := {"metadata": {
		"system_type": "template.envoy:2.1",
		"system_id": "myid",
	}}

	stacks := {
		"stack1": {"selectors": {"systems": {"myid", "id2"}}},
		"stack2": {"selectors": {"systems": {"myid", "id3"}}},
		"stack3": {"selectors": {"systems": {"myid", "id4"}}},
		"stack4": {"selectors": {"systems": {"myid", "id5"}}},
	}

	actual := entry.applicable_stacks with data.styra.stacks as stack_metadata
		with data.self as self
		with data.stacks as stacks

	actual == {"stack1", "stack2"}
}

test_typename_match_major {
	entry.typename_match_major("template.envoy:2.1", "template.envoy:2.0")
	entry.typename_match_major("template.envoy:2.0", "template.envoy:2.1")
	entry.typename_match_major("template.envoy:2.1", "template.envoy:2.1")
	entry.typename_match_major("template.envoy:2", "template.envoy:2")
	entry.typename_match_major("template.envoy:2.1", "template.envoy:2.1-beta")
	entry.typename_match_major("template.envoy:2.1-beta", "template.envoy:2.1")
	not entry.typename_match_major("template.foobar:2.0", "template.envoy:2.0")
	not entry.typename_match_major("template.envoy:2", "template.envoy:3")
	not entry.typename_match_major("template.envoy:3", "template.envoy:2")
	not entry.typename_match_major("template.envoy:3.1", "template.envoy:2.1")
	not entry.typename_match_major("foo", "template.envoy:2.1")
}

test_parse_name_major {
	entry.parse_name_major("template.envoy:2.1") == ["template.envoy", "2"]
	entry.parse_name_major("template.envoy:23.1") == ["template.envoy", "23"]
	entry.parse_name_major("template.foo:3.0") == ["template.foo", "3"]
	entry.parse_name_major("template.foo:4") == ["template.foo", "4"]
	entry.parse_name_major("kubernetes:2") == ["kubernetes", "2"]
	entry.parse_name_major("kubernetes:2.1") == ["kubernetes", "2"]
	entry.parse_name_major("template.envoy:2.1-beta") == ["template.envoy", "2"]
	not entry.parse_name_major("foobar")
}
