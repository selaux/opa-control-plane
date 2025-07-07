package library.v1.stacks.results.envoy.egress.v1

import data.context.system_id

# System rules policies return
# allow bool
# headers map[string]string
#
# Stacks rules policies return
# allow bool
# headers map[string]string
#

# raw eval: 850us
# with applicable_stacks partially evaluated out: 200us
main["allowed"] = allow

decision_type = x {
	allow
	x := "ALLOWED"
}

decision_type = x {
	not allow
	x := "DENIED"
}

main["code"] = code

main["http_status"] = code

main["headers"] = headers

main["outcome"] = {
	"allowed": allow,
	"decision_type": decision_type,
	"code": code,
	"http_status": code,
	"stacks": stacks_outcome,
	"policy_type": "egress",
	"system_type": "envoy",
}

code = x {
	x := stack_status_code
}

code = x {
	x := system_status_code
	not stack_status_code
}

code = 200 {
	allow == true
	not stack_status_code
	not system_status_code
}

code = 403 {
	not allow == true
	not stack_status_code
	not system_status_code
}

# If stack makes an allow/deny decision, that's the decision.  Otherwise, system decides.
# Alternative:
#   if stack.deny, denied.
#   if system.allow or system.deny then that decision.
#   if stack.allow then allow; otherwise deny.
default allow = false

allow {
	stack_allow == true
	not stack_deny == true
}

allow {
	not stack_allow == true
	not stack_deny == true
	system_allow == true
	not system_deny == true
}

stack_allow {
	applicable_stacks[stack_id]
	data.stacks[stack_id].policy["com.styra.envoy.egress"].rules.rules.allow
}

stack_deny {
	applicable_stacks[stack_id]
	data.stacks[stack_id].policy["com.styra.envoy.egress"].rules.rules.allow == false
}

stack_status_codes[x] {
	applicable_stacks[stack_id]
	x := data.stacks[stack_id].policy["com.styra.envoy.egress"].rules.rules.status_code
}

stack_status_code = x {
	count(stack_status_codes) == 1
	stack_status_codes[x]
}

stack_status_code = x {
	count(stack_status_codes) > 1
	x := max(stack_status_codes)
}

system_allow {
	data.policy["com.styra.envoy.egress"].rules.rules.allow
}

# redundant but preserved to standardize computation of "allow" with stacks + systems
system_deny {
	not system_allow
}

system_status_code = x {
	x := data.policy["com.styra.envoy.egress"].rules.rules.status_code
}

applicable_stacks[stack_id] {
	data.stacks[stack_id] = _ # TODO(tsandall): if this becomes a bottleneck we can inject stack ids into data
}

stacks_outcome[stack_id] = x {
	# stacks that set allow to either true or false
	applicable_stacks[stack_id]
	x := {"allowed": data.stacks[stack_id].policy["com.styra.envoy.egress"].rules.rules.allow == true}
}

stacks_outcome[stack_id] = {} {
	# stacks that have allow as undefined
	applicable_stacks[stack_id]
	not data.stacks[stack_id].policy["com.styra.envoy.egress"].rules.rules.allow == data.stacks[stack_id].policy["com.styra.envoy.egress"].rules.rules.allow
}

# stack headers override system headers.
# conflicts within stack headers generate Rego errors
headers[k] = v {
	x := stacks_headers
	x[k] = v
}

headers[k] = v {
	data.policy["com.styra.envoy.egress"].rules.rules.headers[k] = v
	not stacks_headers[k]
}

headers["x-ext-auth-allow"] = ext_auth_allow_value

stacks_headers[k] = v {
	applicable_stacks[stack_id]
	data.stacks[stack_id].policy["com.styra.envoy.egress"].rules.rules.headers[k] = v
}

ext_auth_allow_value = x {
	allow
	x = "yes"
}

ext_auth_allow_value = x {
	not allow
	x = "no"
}
