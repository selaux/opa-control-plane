package library.v1.stacks.decision.v2


import data.context.policy_type
import data.context.system_type
import data.library.v1.utils.object.v1 as util_object

policy_id := sprintf("com.styra.%s.%s", [system_type, policy_type])

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

custom_type := system_labels.custom_type

# backend_system_type = x {
# 	data.styra.systems[index].id == system_id
# 	x := data.styra.systems[index].type
# }

# applicable_stacks[stack_id] {
# 	data.stacks[stack_id].selectors.systems[system_id]

# 	# We use backend_system_type here rather than the system_type passed in the context because the
# 	# backend may identify this system as "kubernetes:v2" but the system type passed in will be "kubernetes"
# 	data.styra.stacks[stack_id].config.type == backend_system_type
# }

stacks[stack_id] = x {
	_ = data.stacks[stack_id]  # TODO(tsandall): if this becomes a bottleneck we can inject stack ids into data

	x := {
		"enforced": {decision | decision := convert(data.stacks[stack_id].policy[policy_id].rules.rules.enforce[_])} | {decision | decision := convert(data.stacks[stack_id].policy[policy_id].rules.rules.deny[_])},
		"monitored": {decision | decision := convert(data.stacks[stack_id].policy[policy_id].rules.rules.monitor[_])},
	}
}



system_enforced[decision] {
	decision := convert(data.policy[policy_id].rules.rules.enforce[_])
}

system_enforced[decision] {
	decision := convert(data.policy[policy_id].rules.rules.deny[_])
}

system_monitored[decision] {
	decision := convert(data.policy[policy_id].rules.rules.monitor[_])
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
	# applicable_stacks[stack_id]
	message := stacks[stack_id].enforced[_].message
}

enforced_messages[message] {
	message := system.enforced[_].message
}

monitored_messages[message] {
	# applicable_stacks[stack_id]
	message := stacks[stack_id].monitored[_].message
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

# system rules that ask for a notification
notifications[n] {
	last_mile_result.outcome.system.enforced[_].notify[n]
}

notifications[n] {
	last_mile_result.outcome.system.monitored[_].notify[n]
}

# stack rules that ask for a notification
notifications[n] {
	# applicable_stacks[stack_id]
	last_mile_result.outcome.stacks[stack_id].enforced[_].notify[n]
}

notifications[n] {
	# applicable_stacks[stack_id]
	last_mile_result.outcome.stacks[stack_id].monitored[_].notify[n]
}

# system metadata notifications policy
notifications[n] {
	data.metadata[system_id].notifications.notify[n] with data.context.outcome as last_mile_result.outcome
}

notifications[n] {
	data.notifications.notify[n] with data.context.outcome as last_mile_result.outcome
}

# workspace notification policy
notifications[n] {
	data.metadata.notifications.notify[n] with data.context.outcome as last_mile_result.outcome
}

# stacks notifications policy
stack_notifications[stack_id] = x {
	# applicable_stacks[stack_id]
	x := data.stacks[stack_id].notifications with data.context.outcome as last_mile_result.outcome
}

notifications[n] {
	stack_notifications[_].notify[n]
}

pre_last_mile_outcome = x {
	x := {
		# "allowed": will be filled in by a last-mile policy.
		"message": message,
		"policy_type": policy_type,
		"stacks": stacks,
		"system": system,
		"system_type": system_type,
	}
}

else = x {
	x := {
		# "allowed": will be filled in by a last-mile policy.
		"policy_type": policy_type,
		"stacks": stacks,
		"system": system,
		"system_type": system_type,
	}
}

last_mile_result = x {
	# Use workspace custom-type last-mile policy if one exists.
	x := data.results[custom_type].policy[policy_id].main with data.context.outcome as pre_last_mile_outcome
}

else = x {
	# Use workspace system-type last-mile policy.
	x := data.results.policy[policy_id].main with data.context.outcome as pre_last_mile_outcome
}

else = x {
	# Use library system-type/policy-type last-mile policy.
	x := data.library.v1.stacks.last_mile.policy[policy_id].v1.main with data.context.outcome as pre_last_mile_outcome
}

outcome[x] = y {
	y := last_mile_result.outcome[x]
}

outcome["notifications"] = notifications

last_mile_no_outcome := {key: val | val := last_mile_result[key]; not util_object["contains"](["outcome"], key)}

result[x] = y {
	y := last_mile_no_outcome[x]
}

result["outcome"] = outcome

# Return undefined if there’s no last-mile policy.

main = x {
	last_mile_result.outcome
	x := result
}

else = x {
	not last_mile_result.outcome
	x := {
		"error": "Invalid result: `outcome` is not defined",
		"given": outcome,
	}
}

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

# main_monitoring returns the set of enforced and monitored messages; this is meant for the monitor policy to consume
main_monitoring = {"messages": msgs} {
	msgs := enforced_messages | monitored_messages
}
