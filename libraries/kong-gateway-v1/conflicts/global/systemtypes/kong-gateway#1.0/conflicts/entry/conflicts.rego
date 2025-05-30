package global.systemtypes["kong-gateway:1.0"].conflicts.entry

# All rules must exist at policy[type]
# Evaluates allow,deny,headers,status_code for conftest compatibility
# stacks always takes precedence for rules
#############################################
# Output construction

# System rules policies return
# allow bool
# deny bool
# headers map[string]string
# status_code string
#
# Stacks rules policies return
# allow bool
# deny bool
# headers map[string]string
# status_code string

default type = "ingress"

main["allowed"] = allow

decision_type = x {
	allow
	x := "ALLOWED"
}

decision_type = x {
	deny
	x := "DENIED"
}

main["code"] = code

main["http_status"] = code

main["headers"] = headers

main["outcome"] = outcome

# include notifications field in outcome only if it is non empty
outcome = x {
	notifications != set()
	x := {
		"allowed": allow,
		"decision_type": decision_type,
		"code": code,
		"http_status": code,
		"stacks": stacks_outcome,
		"policy_type": type,
		"system_type": data.self.metadata.system_type,
		"notifications": notifications,
	}
} else = {
	"allowed": allow,
	"decision_type": decision_type,
	"code": code,
	"http_status": code,
	"stacks": stacks_outcome,
	"policy_type": type,
	"system_type": data.self.metadata.system_type,
}

code = x {
	x := stack_status_code
}

code = x {
	x := system_status_code
	not stack_status_code
}

code = 200 {
	allow
	not stack_status_code
	not system_status_code
}

code = 403 {
	deny
	not stack_status_code
	not system_status_code
}

# If stack makes an allow/deny decision, that's the decision.  Otherwise, system decides.
# Alternative:
#   if stack.deny, denied.
#   if system.allow or system.deny then that decision.
#   if stack.allow then allow; otherwise deny.
default allow = false

deny {
	not allow
}

allow {
	stack_allow
	not stack_deny
}

allow {
	not stack_allow
	not stack_deny
	system_allow
	not system_deny
}

stack_allow {
	data.stacks[stack_id].policy[type].allow
}

stack_deny {
	data.stacks[stack_id].policy[type].deny
}

stack_status_codes[x] {
	x := data.stacks[stack_id].policy[type].status_code
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
	data.policy[type].allow
}

system_deny {
	data.policy[type].deny
}

# redundant but preserved to standardize computation of "allow" with stacks + systems
system_deny {
	not system_allow
}

system_status_code = x {
	x := data.policy[type].status_code
}

stacks_outcome[stack_id] = x {
	# stacks that set allow to true
	_ = data.stacks[stack_id]
	allowed := {decision |
		decision := data.stacks[stack_id].policy[type].allow
	}

	denied := {decision |
		decision := data.stacks[stack_id].policy[type].deny
	}

	x := {
		"allowed": allowed,
		"denied": denied,
	}
}

# stack headers override system headers.
# conflicts within stack headers generate Rego errors
headers[k] = v {
	x := stacks_headers
	x[k] = v
}

headers[k] = v {
	data.policy[type].headers[k] = v
	not stacks_headers[k]
}

headers["x-ext-auth-allow"] = ext_auth_allow_value

stacks_headers[k] = v {
	data.stacks[stack_id].policy[type].headers[k] = v
}

ext_auth_allow_value = x {
	allow
	x = "yes"
}

ext_auth_allow_value = x {
	deny
	x = "no"
}

# notifications

# system metadata notifications policy
notifications[n] {
	data.metadata[system_id].notifications.notify[n] with data.context.outcome as {"allowed": allow}
}

# stacks notifications policies
stack_notifications[stack_id] = x {
	x := data.stacks[stack_id].notifications with data.context.outcome as {"allowed": allow}
}

notifications[n] {
	stack_notifications[_].notify[n]
}
