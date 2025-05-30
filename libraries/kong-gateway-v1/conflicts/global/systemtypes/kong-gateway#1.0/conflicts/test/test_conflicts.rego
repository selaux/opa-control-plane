package conflicts.test

import data.global.systemtypes["kong-gateway:1.0"].conflicts.entry

test_system_ingress_allow {
	system := {"ingress": {"allow": true, "headers": {"foo": "bar"}}}
	metadata := {"system_type": "kong-gateway", "system_id": "myid"}
	input_request := {
		"headers": {
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"accept-encoding": "gzip, deflate",
			"accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
			"cache-control": "max-age=0",
			"connection": "keep-alive",
			"host": "192.168.49.2:30831",
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
		},
		"method": "GET",
		"path": "/foo",
		"remote_address": "172.17.0.1",
	}

	ans := entry.main with data.policy as system
		with data.self.metadata as metadata
		with data.stacks as {}
		with input as input_request

	ans.allowed == true
	ans.headers["x-ext-auth-allow"] == "yes"
	ans.headers.foo == "bar"
	ans.outcome.http_status == 200
	ans.outcome.policy_type == "ingress"
	ans.outcome.stacks == {}

	# notifications should be undefined
	not ans.outcome.notifications == ans.outcome.notifications
}

test_system_ingress_deny {
	system := {"ingress": {"deny": true, "headers": {"foo": "bar"}}}
	metadata := {"system_type": "kong-gateway", "system_id": "myid"}
	input_request := {
		"headers": {
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"accept-encoding": "gzip, deflate",
			"accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
			"cache-control": "max-age=0",
			"connection": "keep-alive",
			"host": "192.168.49.2:30831",
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
		},
		"method": "GET",
		"path": "/foo",
		"remote_address": "172.17.0.1",
	}

	ans := entry.main with data.policy as system
		with data.self.metadata as metadata
		with data.stacks as {}
		with input as input_request

	ans.allowed == false
	ans.headers["x-ext-auth-allow"] == "no"
	ans.headers.foo == "bar"
	ans.outcome.http_status == 403
	ans.outcome.policy_type == "ingress"
	ans.outcome.stacks == {}
}

test_stack_ingress_deny {
	applicable_stacks := {"stack1"}
	stack1 := {"ingress": {"deny": true}}
	metadata := {"system_type": "kong-gateway", "system_id": "myid"}
	input_request := {
		"headers": {
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"accept-encoding": "gzip, deflate",
			"accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
			"cache-control": "max-age=0",
			"connection": "keep-alive",
			"host": "192.168.49.2:30831",
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
		},
		"method": "GET",
		"path": "/foo",
		"remote_address": "172.17.0.1",
	}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.self.metadata as metadata
		with data.stacks.stack1.policy as stack1
		with input as input_request

	ans.allowed == false
	ans.headers["x-ext-auth-allow"] == "no"
	ans.outcome.http_status == 403
	ans.outcome.policy_type == "ingress"
	ans.outcome.decision_type == "DENIED"
	count(ans.outcome.stacks.stack1.denied) == 1
	count(ans.outcome.stacks.stack1.allowed) == 0
	ans.outcome.stacks.stack1.denied[_] == true
}

test_stack_ingress_allow {
	applicable_stacks := {"stack1"}
	metadata := {"system_type": "kong-gateway", "system_id": "myid"}
	stack1 := {"ingress": {"allow": true}}
	input_request := {
		"headers": {
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"accept-encoding": "gzip, deflate",
			"accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
			"cache-control": "max-age=0",
			"connection": "keep-alive",
			"host": "192.168.49.2:30831",
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
		},
		"method": "GET",
		"path": "/foo",
		"remote_address": "172.17.0.1",
	}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.self.metadata as metadata
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
	metadata := {"system_type": "kong-gateway", "system_id": "myid"}
	stack1 := {"ingress": {"allow": true, "deny": true}}
	input_request := {
		"headers": {
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"accept-encoding": "gzip, deflate",
			"accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
			"cache-control": "max-age=0",
			"connection": "keep-alive",
			"host": "192.168.49.2:30831",
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
		},
		"method": "GET",
		"path": "/foo",
		"remote_address": "172.17.0.1",
	}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.self.metadata as metadata
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
}

test_stack_ingress_precedence_over_system {
	applicable_stacks := {"stack1"}
	metadata := {"system_type": "kong-gateway", "system_id": "myid"}
	stack1 := {"ingress": {"allow": true}}
	system := {"ingress": {"deny": true}}
	input_request := {
		"headers": {
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"accept-encoding": "gzip, deflate",
			"accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
			"cache-control": "max-age=0",
			"connection": "keep-alive",
			"host": "192.168.49.2:30831",
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
		},
		"method": "GET",
		"path": "/foo",
		"remote_address": "172.17.0.1",
	}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.self.metadata as metadata
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

test_no_system_no_stacks {
	applicable_stacks := {"stack1"}
	metadata := {"system_type": "kong-gateway", "system_id": "myid"}
	system := {"ingress": {}}
	stack1 := {"ingress": {}}
	input_request := {
		"headers": {
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"accept-encoding": "gzip, deflate",
			"accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
			"cache-control": "max-age=0",
			"connection": "keep-alive",
			"host": "192.168.49.2:30831",
			"upgrade-insecure-requests": "1",
			"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
		},
		"method": "GET",
		"path": "/foo",
		"remote_address": "172.17.0.1",
	}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.self.metadata as metadata
		with data.stacks.stack1.policy as stack1
		with input as input_request
		with data.policy as system

	ans.allowed == false
	ans.headers["x-ext-auth-allow"] == "no"
	ans.outcome.http_status == 403
	ans.outcome.policy_type == "ingress"
	ans.outcome.decision_type == "DENIED"
}

# notifications

test_system_notifications {
	system := {"ingress": {"allow": false, "headers": {"foo": "bar"}}}
	metadata := {"system_type": "kong-gateway", "system_id": "myid"}

	ans := entry.main with data.policy as system
		with data.metadata.myid.notifications as {"notify": {{"channel": "system", "type": "slack"}}}
		with data.self.metadata as metadata
		with data.stacks as {}
		with input as {}

	ans.allowed == false
	ans.outcome.notifications == {{"channel": "system", "type": "slack"}}
}

test_stacks_notifications {
	system := {"ingress": {"allow": false, "headers": {"foo": "bar"}}}
	metadata := {"system_type": "kong-gateway", "system_id": "myid"}

	ans := entry.main with data.policy as system
		with data.self.metadata as metadata
		with input as {}
		with data.metadata.myid.notifications as {"notify": {{"channel": "system", "type": "slack"}}}
		with data.stacks.stack123.notifications as {"notify": {{"channel": "stack", "type": "test"}}}

	ans.allowed == false
	ans.outcome.notifications == {
		{"channel": "system", "type": "slack"},
		{"channel": "stack", "type": "test"},
	}
}
