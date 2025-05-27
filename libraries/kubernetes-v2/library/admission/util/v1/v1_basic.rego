package library.v1.kubernetes.admission.util.v1

# compute a new object that is a reduction of a given object by removing the given keys
reduce_object_blacklist(obj, keys) = newobj {
	newobj := {k: v | v := obj[k]; not keys[k]}
}

# compute a new obj that has the union of the keys from the 2 given objects
merge_objects(obj1, obj2) = obj {
	allkeys := {k | obj1[k]} | {k | obj2[k]}
	obj := {k: v | allkeys[k]; v := either(k, obj1, obj2)}
}

either(key, obj1, obj2) = x {
	x := obj1[key]
}

else = x {
	x := obj2[key]
}

get(params, key, def) = def {
	not params[key]
}

get(params, key, def) = x {
	x := params[key]
}

# This is used to restrict the applicable network policies to
# k8s defined v1 version policies.
is_network_policy {
	input.request.kind.kind == "NetworkPolicy"
	input.request.kind.group == "networking.k8s.io"
	input.request.kind.version == "v1"
}

# With k8s versions, 1.15 and below the NetworkPolicy kind supports
# both apiVersions networking.k8s.io/v1 and extensions/v1beta1.
is_network_policy {
	input.request.kind.kind == "NetworkPolicy"
	input.request.kind.group == "extensions"
	input.request.kind.version == "v1beta1"
}

# blacklist is a map of protocol and port numbers.
#  E.g., TCP: [123, 345]
# This verifies that any member of the ports (list of port) is in blacklist
ports_in_blacklist(blacklist, ports) {
	single_port := ports[_]
	blacklist[single_port.protocol][single_port.port]
}

selector_blacklist_match(expected, selector) {
	not selector.matchLabels
}

selector_blacklist_match(expected, selector) {
	all_keys := {key | some key; selector.matchLabels[key] = _}
	any_match(expected, selector.matchLabels, all_keys)
}

selector_match(expected, selector) {
	not selector.matchLabels
}

selector_match(expected, selector) {
	all_keys := {key | some key; selector.matchLabels[key] = _}
	not any_not_match(expected, selector.matchLabels, all_keys)
}

any_not_match(expected, labels, all_keys) {
	all_keys[key]
	not label_match(expected, labels, key)
}

any_match(expected, labels, all_keys) {
	all_keys[key]
	label_match(expected, labels, key)
}

label_match(expected, labels, key) {
	# here labels[key] is one string while expected[key] is a list
	val := expected[key][_]
	glob.match(val, [], labels[key])
}

label_match(expected, labels, key) {
	# An empty set means the value does not matter.
	expected[key] == {}
}

# whitelist is a map of protocol and port numbers.
#  E.g., TCP: [123, 345]
# This verifies that every member of the ports (list of port) is in whitelist
ports_in_whitelist(whitelist, ports) {
	not any_not_match_port(whitelist, ports)
}

any_not_match_port(whitelist, ports) {
	single_port := ports[_]
	not port_match(whitelist, single_port)
}

port_match(whitelist, single_port) {
	whitelist[single_port.protocol][single_port.port]
}

port_match(whitelist, single_port) {
	not single_port.port
}

modify_ops = {"UPDATE", "CREATE"}

is_service_account {
	# https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens
	startswith(input.request.userInfo.username, "system:serviceaccount:")
	is_service_account_group_ns
	is_service_account_group
}

is_service_account_group {
	input.request.userInfo.groups[_] == "system:serviceaccounts"
}

is_service_account_group_ns {
	startswith(input.request.userInfo.groups[_], "system:serviceaccount:")
}

is_create_or_update {
	input.request.operation == "CREATE"
}

is_create_or_update {
	input.request.operation == "UPDATE"
}
