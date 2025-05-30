package global.systemtypes["terraform:2.0"].library.utils.v1

import data.exemptions
import future.keywords.every
import future.keywords.in

# Return plan resources from resource_changes with:
#   - no actions (for state and code),
#   - empty actions, or
#   - actions, other than "delete" only
plan_resource_changes[resource] {
	some resource in input.resource_changes
	allowed_resource_actions(resource)
}

allowed_resource_actions(resource) {
	not is_key_defined(resource.change, "actions")
}

allowed_resource_actions(resource) {
	count(resource.change.actions) == 0
}

allowed_resource_actions(resource) {
	supported_rule_resource_actions[_] in resource.change.actions
}

supported_rule_resource_actions := {"create", "update", "no-op", "read"}

build_metadata_return(meta, params, resource, context) := x {
	x := {
		"rule": {
			"id": get_or_default(meta, ["custom", "id"]),
			"title": get_or_default(meta, ["title"]),
			"severity": get_or_default(meta, ["custom", "severity"]),
			"resource_category": get_or_default(meta, ["custom", "resource_category"]),
			"control_category": get_or_default(meta, ["custom", "control_category"]),
			"rule_link": get_or_default(meta, ["custom", "rule_link"]),
			"compliance_pack": null,
			"description": get_or_default(meta, ["description"]),
			"impact": get_or_default(meta, ["custom", "impact"]),
			"remediation": get_or_default(meta, ["custom", "remediation"]),
			"platform": get_or_default(meta, ["custom", "platform", "name"]),
			"provider": get_or_default(meta, ["custom", "provider", "name"]),
			"rule_targets": get_or_default(meta, ["custom", "rule_targets"]),
			"parameters": params,
		},
		"resource": {
			"module": module_type(resource),
			"type": get_or_default(resource, ["type"]),
			"address": get_or_default(resource, ["address"]),
			"name": get_or_default(resource, ["name"]),
			"actions": get_or_default(resource, ["change", "actions"]),
			"context": context,
		},
	}
}

get_or_default(obj, key) := val {
	val := object.get(obj, key, null)
} else := null

module_type(resource) := x {
	x := resource.module_address
}

module_type(resource) := x {
	not resource.module_address
	x := "root_module"
}

# Checks if a particular key is defined inside an object or not
# Returns true if key is defined
# Returns false if key is not defined
is_key_defined(obj, key) {
	_ = obj[key]
}

# Checks whether an element is present in an array or not
# Returns true if element 'e' is present in array 'arr', else returns false
is_element_present(arr, e) {
	e in arr
}

# Walks traversely through configuration section of tf input json
# Flattens the configuration resources
plan_configuration := {r |
	some path, value
	walk(input.configuration, [path, value])
	rs := flatten_module_configs(path, value)
	r := rs[_]
}

# Unions the configuration of resources from root module and child modules
flatten_module_configs(path, value) := rs {
	root_resources := root_module_configs(path, value)
	child_resources := child_module_configs(path, value)
	rs := root_resources | child_resources
}

# Fetches the configuration of resources from root module
root_module_configs(path, value) := {rs |
	# Expected object:
	#     {
	#     	"root_module": {
	#         "resources": [...],
	#         ...
	#       }
	#     }
	# Where the path is [..., "root_module", "resources"]
	reverse_index(path, 1) == "root_module"
	resource := value.resources[_]
	final_value := json.patch(resource, [{"op": "add", "path": "/module_address", "value": "root_module"}])
	rs := final_value
}

# Fetches the configuration of resources from child modules
child_module_configs(path, value) := {rs |
	# Expected object:
	#     {
	#       "module_calls": [
	#         "good_sub_instance": {
	#           "module": {
	#             "resources": [...],
	#             ...
	#           }
	#         }
	#       ]
	#     }
	# Where the path is [..., "module_calls", "", "module", "resources"]
	# Note: there will always be a key string between `module_calls` and
	# `module` and there may be mulitple levels of nested child modules.
	reverse_index(path, 1) == "module"
	reverse_index(path, 3) == "module_calls"
	resource := value.resources[_]
	module_address := replace(concat(".", ["module", concat(".", array.slice(path, 2, count(path) - 1))]), "module_calls.", "")
	new_addr := concat(".", [module_address, resource.address])
	final_value := json.patch(resource, [{"op": "add", "path": "/address", "value": new_addr}, {"op": "add", "path": "/module_address", "value": module_address}])
	rs := final_value
}

# Checks the value in path (one index above) while traversing through path
reverse_index(path, idx) := value {
	value := path[count(path) - idx]
}

# Checks if a violation is included by a given filter
input_includes_requirements(filter, violation) {
	# Include, if no actions on violating resource
	not violation.metadata.resource.actions
} else {
	# Include, if no actions on violating resource
	violation.metadata.resource.actions == null
} else {
	# Include, if no actions on violating resource
	count(violation.metadata.resource.actions) == 0
} else {
	action := filter.actions[_]
	violation_has_action(action, violation)
} else = false

# Checks if a violation is excluded by a given filter
input_excludes_requirements(filter, violation) {
	every action in filter.actions {
		not violation_has_action(action, violation)
	}
} else = false

violation_has_action("create", violation) {
	violation.metadata.resource.actions == ["create"]
}

violation_has_action("delete", violation) {
	"delete" in violation.metadata.resource.actions
	not "create" in violation.metadata.resource.actions
}

violation_has_action("replace", violation) {
	object.subset(violation.metadata.resource.actions, {"create", "delete"})
}

violation_has_action(action, violation) {
	not action in {"create", "delete", "replace"}
	action in violation.metadata.resource.actions
}

get_exemption(decision) := exemption {
	id := decision.metadata.rule.id
	exemption := exemptions["exemptions.json"].rules[id].targets[target_id]
	decision.metadata.resource.address == target_id
	not is_expired(exemption)
}

is_exempted(decision) {
	get_exemption(decision)
} else := false

is_expired(exemption) {
	time.now_ns() > time.parse_rfc3339_ns(exemption.expires)
}

default exemptions_present := false

exemptions_present {
	count(exemptions["exemptions.json"].rules) > 0
}
