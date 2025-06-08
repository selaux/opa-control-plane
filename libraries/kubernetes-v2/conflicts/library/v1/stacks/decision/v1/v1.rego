package library.v1.stacks.decision.v1

import data.context.policy

# TODO(tsandall): only metadata for specific system will be included in bundle
# so this import is not necessary and the entrypoint will not provide it
# import data.context.system_id

system_features = x {
	x := data.metadata[system_id].features
}

else = x {
	x := {}
}

system_labels = x {
	x := data.metadata[system_id].labels.labels
}

else = x {
	x := {}
}

# system_type = x {
# 	data.styra.systems[index].id == system_id
# 	x := data.styra.systems[index].type
# }

custom_type = system_labels.custom_type

applicable_stacks[stack_id] {
    # TODO(tsandall): replace w/ builtin stack id list
    data.stacks[stack_id] = _
}

stacks[stack_id] = x {
	applicable_stacks[stack_id]

	x := {
		"enforced": {decision | decision := convert(data.stacks[stack_id].admission_control.enforce[_])} | {decision | decision := convert(data.stacks[stack_id].admission_control.deny[_])},
		"monitored": {decision | decision := convert(data.stacks[stack_id].admission_control.monitor[_])},
	}
}

# TODO: Choose between compatibility or migration. Or devise a way to facilitate
# both compatibility and, for performance-sensitive systems, incompatibility.
# Add fixtures and tests as appropriate.

# Assumes reason strings reflect denied decisions and wraps them in structured
# decision objects for compatibility.
convert(decision) = x {
	is_string(decision)

	x := {
		"allowed": false,
		"message": decision,
	}
}

else = x {
	x := decision
}

# Queries `deny` rules for compatibility (which shouldn’t be any more expensive
# than querying the same rule had it been named `enforce`).
system_enforced[decision] {
	decision := convert(data.admission_control.deny[_])
}

system_enforced[decision] {
	decision := convert(data.admission_control.enforce[_])
}

system_monitored[decision] {
	decision := convert(data.admission_control.monitor[_])
}

system = x {
	x := {
		"enforced": system_enforced,
		"features": system_features,
		"labels": system_labels,
		"monitored": system_monitored,
	}
}

enforced_messages[message] {
	message := stacks[_].enforced[_].message
}

enforced_messages[message] {
	message := system.enforced[_].message
}

monitored_messages[message] {
	message := stacks[_].monitored[_].message
}

monitored_messages[message] {
	message := system.monitored[_].message
}

enforced_message = concat(", ", enforced_messages)

monitored_message = concat(", ", monitored_messages)

message = x {
	enforced_message != ""
	monitored_message != ""
	x := sprintf("Enforced: %v, Monitored: %v", [enforced_message, monitored_message])
}

else = x {
	enforced_message != ""
	x := sprintf("Enforced: %v", [enforced_message])
}

else = x {
	monitored_message != ""
	x := sprintf("Monitored: %v", [monitored_message])
}

outcome = x {
	x := {
		# "allowed": To be filled in by a last-mile policy.
		"message": message,
		"stacks": stacks,
		"system": system,
		"policy_type": policy,
	}
}

else = x {
	x := {
		# "allowed": To be filled in by a last-mile policy.
		"stacks": stacks,
		"system": system,
		"policy_type": policy,
	}
}

result = x {
	# Use workspace custom-type last-mile policy if one exists.
	x := data.results[custom_type].admission_control.main with data.context.outcome as outcome
}

else = x {
	# Use workspace system-type last-mile policy.
	x := data.results.kubernetes.admission_control.main with data.context.outcome as outcome
}

else = x {
	# Use library system-type last-mile policy.
	x := data.library.v1.stacks.results.kubernetes.admission_control.v1.main with data.context.outcome as outcome
}

# Return undefined if there’s no last-mile policy.

main = x {
	x := result
	x.outcome.allowed = _
}

else = x {
	not result
	x := {
		"error": "Missing result",
		"given": outcome,
	}
}

else = x {
	not result.outcome
	x := {
		"error": "Invalid result: `outcome` is not defined",
		"given": outcome,
	}
}

else = x {
	not result.outcome.allowed
	x := {
		"error": "Invalid result: `outcome.allowed` is not defined",
		"given": outcome,
	}
}

main_monitoring = {"messages": msgs} {
	msgs := enforced_messages | monitored_messages
}