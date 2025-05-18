package TYPELIB.conflicts.entry

# System and stack rules policies must exist at policy[type]
# System and stack rules return
# allow bool
# deny bool
# headers map[string]string
# status_code number
# body string

#############################################
# Output construction

envoyPolicyTypes = ["ingress", "egress"]

default type = "ingress"

type = inputType {
	# deprecated (envoy v2 API input)
	envoyPolicyTypes[x] = input.attributes.metadata_context.filter_metadata["envoy.filters.http.header_to_metadata"].fields.policy_type.Kind.StringValue
	inputType := envoyPolicyTypes[x]
}

type = inputType {
	# deprecated (envoy v2 API input) + account for change in marshalling function for opa-envoy v0.24.0+
	# https://github.com/open-policy-agent/opa-envoy-plugin/pull/219
	envoyPolicyTypes[x] = input.attributes.metadata_context.filter_metadata["envoy.filters.http.header_to_metadata"].policy_type
	inputType := envoyPolicyTypes[x]
}

type = inputType {
	# envoy v3 API input
	envoyPolicyTypes[x] = input.attributes.metadataContext.filterMetadata["envoy.filters.http.header_to_metadata"].policy_type
	inputType := envoyPolicyTypes[x]
}

main["allowed"] = allow

decision_type = x {
	allow
	x := "ALLOWED"
}

decision_type = x {
	not allow
	x := "DENIED"
}

main["code"] = status_code

main["http_status"] = status_code

main["headers"] = headers

main["body"] = body

main["custom"] = custom

main["response_headers_to_add"] = response_headers_to_add

main["request_headers_to_remove"] = request_headers_to_remove

main["outcome"] = {
	"allowed": allow,
	"decision_type": decision_type,
	"code": status_code,
	"http_status": status_code,
	"stacks": stacks_outcome,
	"policy_type": type,
	"system_type": data.self.metadata.system_type,
}

stacks_outcome[stack_id] = x {
	# stacks that set allow to true
	applicable_stacks[stack_id]
	allowed := {decision | decision := data.stacks[stack_id].policy[type].allow}
	denied := {decision | decision := data.stacks[stack_id].policy[type].deny}

	x := {
		"allowed": allowed,
		"denied": denied,
	}
}

###########################################
# Augment stack/system decision as needed

# always return a status code
status_code = x {
	x := the_status_code
}

status_code = 200 {
	not the_status_code
	allow
}

status_code = 403 {
	not the_status_code
	not allow
}

# headers augmented with x-ext-auth-allow, when missing
# stacks/systems should NOT provide this, but they could
headers[x] = y {
	the_headers[x] = y
}

headers["x-ext-auth-allow"] = ext_auth_allow_value {
	not the_headers["x-ext-auth-allow"]
}

ext_auth_allow_value = "yes" {
	allow
}

ext_auth_allow_value = "no" {
	not allow
}

###########################################
# Combine stacks/system to make a decision

# If a stack makes either an allow/deny decision, stack is responsible for
#    entire return value.  Otherwise, system responsible for return value.
# If multiple stacks make decisions, a deny stack is responsible for return.
# If multiple deny stacks, then the one with the highest 'priority' makes
#    the decision.  (If multiple of those, pick alphabetical on ID.)
# Any of these fields, except 'allow', are undefined
#     exactly when the stack/system field is undefined

default allow = false

allow = the_stack_allowed {
	the_stack_id
}

allow = the_system_allowed {
	not the_stack_id
}

the_status_code = the_stack_status_code {
	the_stack_id
}

the_status_code = the_system_status_code {
	not the_stack_id
}

the_headers = the_stack_headers {
	the_stack_id
}

the_headers = the_system_headers {
	not the_stack_id
}

body = the_stack_body {
	the_stack_id
}

body = the_system_body {
	not the_stack_id
}

response_headers_to_add = the_stack_response_headers_to_add {
	the_stack_id
}

response_headers_to_add = the_system_response_headers_to_add {
	not the_stack_id
}

request_headers_to_remove = the_stack_request_headers_to_remove {
	the_stack_id
}

request_headers_to_remove = the_system_request_headers_to_remove {
	not the_stack_id
}

custom = the_stack_custom {
	the_stack_id
}

custom = the_system_custom {
	not the_stack_id
}

the_stack_allowed {
	not data.stacks[the_stack_id].policy[type].deny
	data.stacks[the_stack_id].policy[type].allow
}

the_system_allowed {
	not data.policy[type].deny
	data.policy[type].allow
}

# shorthand
the_stack_headers = data.stacks[the_stack_id].policy[type].headers

the_system_headers = data.policy[type].headers

the_stack_body = data.stacks[the_stack_id].policy[type].body

the_system_body = data.policy[type].body

the_stack_status_code = data.stacks[the_stack_id].policy[type].status_code

the_system_status_code = data.policy[type].status_code

the_stack_response_headers_to_add = data.stacks[the_stack_id].policy[type].response_headers_to_add

the_system_response_headers_to_add = data.policy[type].response_headers_to_add

the_stack_request_headers_to_remove = data.stacks[the_stack_id].policy[type].request_headers_to_remove

the_system_request_headers_to_remove = data.policy[type].request_headers_to_remove

the_stack_custom = data.stacks[the_stack_id].policy[type].custom

the_system_custom = data.policy[type].custom

system_allow {
	data.policy[type].allow
}

system_deny {
	data.policy[type].deny
}

# not used any longer, but in case needed for backward compatibility of customer tests
default deny = false

deny {
	not allow
}

# Pick a stack.  If no stacks, then the_stack_id is empty
#   If any deny, consider just those.
#   Else if any allow, consider just those.
#   Then pick the stack with the highest priority (the lowest number, so priority 1 is higher than priority 2)
#      If 0 or 2+ such stacks, pick the first, according to iteration order.
considered_stacks = array.concat(deny_stacks, allow_stacks) # allow_stacks is empty if deny_stacks is not

stack_priorities = {data.stacks[stack_id].policy[type].priority | stack_id := considered_stacks[_]}

highest_stack_prioirty = min(stack_priorities)

chosen_stacks = considered_stacks {
	not highest_stack_prioirty
}

chosen_stacks = result {
	highest_stack_prioirty
	result := [stack_id |
		stack_id := considered_stacks[_]
		data.stacks[stack_id].policy[type].priority == highest_stack_prioirty
	]
}

the_stack_id = chosen_stacks[0]

default deny_stacks = []

deny_stacks = [stack_id |
	some stack_id
	applicable_stacks[stack_id]
	data.stacks[stack_id].policy[type].deny
]

default allow_stacks = []

allow_stacks = result {
	count(deny_stacks) == 0 # skip computing if already a deny_stack
	result := [stack_id |
		some stack_id
		applicable_stacks[stack_id]
		data.stacks[stack_id].policy[type].allow
	]
}

###########################################
# Compute applicable stacks

applicable_stacks[stack_id] {
	some stack_id
	stack := data.styra.stacks[stack_id]
	typename_match_major(stack.config.type, data.self.metadata.system_type)
	data.stacks[stack_id].selectors.systems[data.self.metadata.system_id]
}

typename_match_major(typename1, typename2) {
	typename1 == typename2
} else {
	parse_name_major(typename1) == parse_name_major(typename2)
}

# "template.envoy:2.1" ==> ["template.envoy", "2"]
# ensure we use only OLD opa builtins (no indexof_n)
parse_name_major(name) = [typename, major] {
	index := indexof(name, ":") # index of :
	index != -1
	typename = substring(name, 0, index)
	version := substring(name, index + 1, -1) # 2.1
	major := split(version, ".")[0]
}
