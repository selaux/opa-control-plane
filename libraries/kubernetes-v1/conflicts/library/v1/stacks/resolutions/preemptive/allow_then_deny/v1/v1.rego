package library.v1.stacks.resolutions.preemptive.allow_then_deny.v1

# Use allow-then-deny order to resolve conflicts.
#
#    1. Stacks:
#       a. Deny with `priority == "maximum"` (e.g., untrusted networks)
#       b. Allow with `priority == "maximum"` (e.g., superusers)
#       c. Deny
#       d. Allow
#    2. System:
#       a. Deny with `priority == "maximum"`
#       b. Allow with `priority == "maximum"`
#       c. Deny
#       d. Allow

import data.context.options # e.g., `{"allowed": true}` to fail open
import data.context.outcome # outcome must not contain an "allowed" field

stacks = outcome.stacks

system = outcome.system

# main is the result rule. It includes the outcome with the allowed field filled in

main[key] = val {
	outcome[key] = val
}

main["allowed"] = allowed

allowed = false {
	stacks_priority_denied
}

else {
	stacks_priority_allowed
}

else = false {
	stacks_denied
}

else {
	stacks_allowed
}

else = false {
	system_priority_denied
}

else {
	system_priority_allowed
}

else = false {
	system_denied
}

else {
	system_allowed
}

else = x {
	x := options.allowed
}

stacks_priority_allowed {
	# Stacks can use `{"allowed": true, "priority": "maximum"}` to explicitly
	# allow all other decisions (e.g., in order to authorize superusers).
	decision := stacks[_].enforced[_]
	decision.allowed == true
	decision.priority == "maximum"
}

stacks_priority_denied {
	# Similarly they can use `{"allowed": false, "priority": "maximum"}` to
	# explicitly forbid all other decisions (e.g., in order to prevent any request
	# from being authorized if it originates outside of a trusted network).
	decision := stacks[_].enforced[_]
	decision.allowed == false
	decision.priority == "maximum"
}

system_priority_allowed {
	# Systems can use `{"allowed": true, "priority": "maximum"}` to explicitly
	# allow all other decisions (e.g., in order to authorize senior team members).
	decision := system.enforced[_]
	decision.allowed == true
	decision.priority == "maximum"
}

system_priority_denied {
	# Similarly they can use `{"allowed": false, "priority": "maximum"}` to
	# explicitly forbid all other decisions (e.g., in order to prevent any request
	# from being authorized if it originates with an unknown service).
	decision := system.enforced[_]
	decision.allowed == false
	decision.priority == "maximum"
}

stacks_allowed {
	decision := stacks[_].enforced[_]
	decision.allowed == true
}

stacks_denied {
	decision := stacks[_].enforced[_]
	decision.allowed == false
}

system_allowed {
	decision := system.enforced[_]
	decision.allowed == true
}

system_denied {
	decision := system.enforced[_]
	decision.allowed == false
}
