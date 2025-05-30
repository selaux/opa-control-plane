package global.systemtypes["terraform:2.0"].conflicts.entry

import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import future.keywords.in

# All rules must exist at policy[provider][resource] package level
# Evaluates enforce[] and monitor[] along with deny[] and warn[]

#############################################
# Output construction

main := {
	"allowed": allow,
	"outcome": outcome,
}

outcome := {
	"allow": allow,
	"reason": reason,
	"decisions": combined,
	"decision_type": decision_type,
	"stacks": stacks_outcomes,
	"policy_type": "rules",
	"system_type": data.self.metadata.system_type,
}

default allow := false

allow {
	not deny
}

decision_type := "ALLOWED" {
	allow
}

decision_type := "DENIED" {
	not allow
}

##########################################
# Construct final decision and reasons

deny {
	enforced_decisions := {d |
		combined.enforce[d]
		d.allowed == false
	}

	count(enforced_decisions) > 0
}

reason["FAIL"] = {m |
	combined.enforce[d]
	d.allowed == false
	m := d.message
}

reason["WARN"] = {m | m := combined.monitor[_].message}

#############################################
# Combine stacks and systems

# System and Stack rules return a set of
# {"allowed": bool, "message": string, "metadata": object}

combined["enforce"] = system_enforce | all_stack_enforce

combined["monitor"] = system_monitor | all_stack_monitor

# FIXME: Optimize; we're doing double work for all decisions
combined["exemption"] := system_exemption | all_stack_exemption

all_stack_enforce[decision] {
	some stack_id
	stacks_outcomes[stack_id].enforced[decision]
	not utils.is_exempted(decision)
}

all_stack_monitor[decision] {
	some stack_id
	stacks_outcomes[stack_id].monitored[decision]
	not utils.is_exempted(decision)
}

all_stack_exemption := {decorated_decision |
	utils.exemptions_present # Only do the work if there are exemptions to uphold

	some stack_id
	stacks_outcomes[stack_id][_][decision]
	exemption := utils.get_exemption(decision)
	decorated_decision := object.union(decision, {"exemption": exemption})
}

#############################################
# System processing

system_enforce[decision] {
	some provider, resource
	data.policy[provider][resource].enforce[d]
	decision := canonical_decision(d, false)
	not utils.is_exempted(decision)
}

system_enforce[decision] {
	some provider, resource
	data.policy[provider][resource].deny[d]
	decision := canonical_decision(d, false)
	not utils.is_exempted(decision)
}

system_monitor[decision] {
	some provider, resource
	data.policy[provider][resource].monitor[d]
	decision := canonical_decision(d, true)
	not utils.is_exempted(decision)
}

system_monitor[decision] {
	some provider, resource
	data.policy[provider][resource].warn[d]
	decision := canonical_decision(d, true)
	not utils.is_exempted(decision)
}

system_exemption[decorated_decision] {
	utils.exemptions_present # Only do the work if there are exemptions to uphold

	some provider, resource, action
	action in {"monitor", "warn", "enforce", "deny"}
	data.policy[provider][resource][action][d]
	allowed := action in {"monitor", "warn"}
	decision := canonical_decision(d, allowed)
	exemption := utils.get_exemption(decision)
	decorated_decision := object.union(decision, {"exemption": exemption})
}

canonical_decision(decision, default_allowed) = x {
	x := {
		"allowed": object.get(decision, "allowed", default_allowed),
		"message": decision.message,
		"metadata": object.get(decision, "metadata", null),
	}
}

#############################################
# Stack processing

# Need to return this for time series.
# Call canonical_decision() everywhere to handle user confusion.
stacks_outcomes[stack_id] = x {
	applicable_stacks[stack_id]
	enforced := {decision |
		d := data.stacks[stack_id].policy[_][_].enforce[_]
		decision := canonical_decision(d, false)
	}

	denied := {decision |
		d := data.stacks[stack_id].policy[_][_].deny[_]
		decision := canonical_decision(d, false)
	}

	monitored := {decision |
		d := data.stacks[stack_id].policy[_][_].monitor[_]
		decision := canonical_decision(d, true)
	}

	warned := {decision |
		d := data.stacks[stack_id].policy[_][_].warn[_]
		decision := canonical_decision(d, true)
	}

	x := {
		"enforced": enforced | denied,
		"monitored": monitored | warned,
	}
}

applicable_stacks := {stack_id |
	# data.styra.stacks[stack_id].config.type == data.self.metadata.system_type
	# data.stacks[stack_id].selectors.systems[data.self.metadata.system_id]
	data.stacks[stack_id] = _
}
