package library.v1.kubernetes.admission.network.v1

import data.library.parameters
import data.library.v1.kubernetes.admission.util.v1 as util
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Restrict Hostnames"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require ingress hostnames to match one of the globs you specify.
# suggestions:
#   schema: network_ingresses_all_hostnames
# schema:
#   type: object
#   properties:
#     whitelist:
#       type: array
#       title: "Expressions (Example: apps.*.example.com)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - whitelist

deny_ingress_hostname_not_in_whitelist[reason] {
	count(parameters.whitelist) > 0
	input.request.kind.kind == "Ingress"
	util.is_create_or_update
	host := input.request.object.spec.rules[_].host
	not fqdn_matches_any(host, parameters.whitelist)
	reason := sprintf("Ingress uses an invalid hostname %q.", [host])
}

fqdn_matches_any(str, patterns) {
	fqdn_matches(str, patterns[_])
}

fqdn_matches(str, pattern) {
	pattern_parts := split(pattern, ".")
	pattern_parts[0] == "*"
	str_parts := split(str, ".")
	n_pattern_parts := count(pattern_parts)
	n_str_parts := count(str_parts)
	n_pattern_parts == n_str_parts
	suffix = trim(pattern, "*.")
	endswith(str, suffix)
}

fqdn_matches(str, pattern) {
	not contains(pattern, "*")
	str == pattern
}

network_ingresses_all_hostnames["whitelist"] = arr {
	arr = {x |
		data.library.v1.kubernetes.monitor.v2.namespaced_objects_kind[["ingresses", resource, params]]
		resource.kind == "Ingress"
		x = resource.spec.rules[_].host
	}
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Require TLS"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: Require all ingresses to have Transport Layer Security (TLS) configured.
# suggestions:

ingress_missing_tls[reason] {
	input.request.kind.kind == "Ingress"
	not input.request.object.spec.tls
	reason := sprintf("Resource %v should have TLS enabled.", [utils.input_id])
}

ingress_missing_tls[reason] {
	input.request.kind.kind == "Ingress"
	entry := input.request.object.spec.tls[_]
	bad_tls_entry(entry)
	reason := sprintf("Resource %v should have TLS enabled.", [utils.input_id])
}

bad_tls_entry(entry) {
	not entry.hosts
}

bad_tls_entry(entry) {
	not entry.secretName
}

bad_tls_entry(entry) {
	count(entry.hosts) == 0
}

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict hostPorts"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Ensure containers access allowed hostPorts only.
# schema:
#   type: object
#   properties:
#     host_port_ranges:
#       type: array
#       title: Min-max hostPorts ranges (eg. 1-100)
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - host_port_ranges
#   hint:order:
#     - host_port_ranges

enforce_pod_hostports_whitelist[reason] {
	count(parameters.host_port_ranges) > 0
	container := utils.input_all_container[_]
	hostport := container.ports[_].hostPort
	not utils.value_in_ranges(hostport, parameters.host_port_ranges)
	reason := sprintf("Resource %v runs with prohibited hostPort %v.", [utils.input_id, hostport])
}

# METADATA: library-snippet
# version: v1
# title: "Pod: Prohibit Containers From Sharing HostPID or HostIPC Namespace"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Expect hostPID and hostIPC to be set to false.
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet

deny_host_namespace_sharing[reason] {
	object := utils.get_object(input.request)
	check_object_share_host_namespace(object.spec)
	reason := sprintf("Resource %v has hostPID or hostIPC is set true in pod spec and this is not allowed.", [utils.input_id])
}

check_object_share_host_namespace(spec) {
	spec.hostPID
}

check_object_share_host_namespace(spec) {
	spec.hostIPC
}

# Helpers

paths_conflict_prefix(pathset1, pathset2) {
	nonregex1 := {trim(path, "/") | pathset1[path]; regex.match("[a-zA-Z0-9-./]", path)}
	nonregex2 := {trim(path, "/") | pathset2[path]; regex.match("[a-zA-Z0-9-./]", path)}
	nonregex1[p1]
	nonregex2[p2]
	not isempty(p1)
	not isempty(p2)
	prefix(p1, p2)
}

prefix(p1, p2) {
	startswith(p1, p2)
}

prefix(p1, p2) {
	startswith(p2, p1)
}

isempty(s) {
	count(trim(s, " ")) == 0
}

# "host" field not present in the new Ingress rule.
# This means the Ingress rule applies for all inbound traffic.
# The existence of an Ingress rule in any other namespace would result in a conflict.
ingress_nohost_conflict[reason] {
	input.request.kind.kind == "Ingress"
	count({r | r = input.request.object.spec.rules[_]; trace(sprintf("!!Rule = %v", [r])); not r.host}) > 0
	existing := data.kubernetes.resources.ingresses[ns][name]
	[name, ns] != [input.request.object.metadata.name, input.request.object.metadata.namespace]
	reason := sprintf("%v conflicts with every other ingress, e.g. %v/%v.", [utils.input_id, ns, name])
}

# "host" field not present in existing Ingress rule.
# This means the Ingress rule applies for all inbound traffic.
# The existence of any other Ingress rule would result in a conflict.
ingress_nohost_conflict[reason] {
	input.request.kind.kind == "Ingress"
	count({r | r = input.request.object.spec.rules[_]; not r.host}) == 0

	# find existing ingress not identical to `input`
	existing := data.kubernetes.resources.ingresses[ns][name]
	[name, ns] != [input.request.object.metadata.name, input.request.object.metadata.namespace]

	# that existing ingress has a rule without a host
	rule := existing.spec.rules[_]
	not rule.host
	reason := sprintf("%v conflicts with existing ingress %v/%v, which serves all traffic", [utils.input_id, ns, name])
}

# METADATA: library-snippet
# version: v1
# title: "Egresses: Restrict IP Blocks"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require that `NetworkPolicy` resources define egress rules only within approved IP
#   address ranges.
# suggestions:
#   schema: network_policies_all_egress_cidrs
# schema:
#   type: object
#   properties:
#     whitelist:
#       type: array
#       title: "CIDR IP addresses (Example: 172.17.0.0/16)"
#       description: Approved IP address ranges
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - whitelist

deny_egress_ip_block_not_in_whitelist[reason] {
	# all egress traffic allowed
	network_policy_allows_all_egress
	reason := sprintf("%v allows access to any IP address.", [utils.input_id])
}

deny_egress_ip_block_not_in_whitelist[reason] {
	count(parameters.whitelist) > 0

	# fail if any IP egress targets is not contained in one of the allowed CIDRs
	input.request.kind.kind == "NetworkPolicy"
	input.request.object.spec.policyTypes[_] == "Egress"
	ipBlock := input.request.object.spec.egress[_].to[_].ipBlock
	not any({t | t = net.cidr_contains(parameters.whitelist[_], ipBlock.cidr)})
	reason := sprintf("%v allows egress traffic outside of allowed IP ranges.", [utils.input_id])
}

network_policies_all_egress_cidrs["whitelist"] = arr {
	arr = {x |
		data.library.v1.kubernetes.monitor.v2.namespaced_objects_kind[["networkpolicies", resource, params]]
		resource.kind == "NetworkPolicy"
		resource.spec.policyTypes[_] == "Egress"
		x = resource.spec.egress[_].to[_].ipBlock.cidr
	}
}

# METADATA: library-snippet
# version: v1
# title: "Egresses: Prohibit IP Blocks"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Prevent `NetworkPolicy` resources from defining any egress rules within
#   prohibited IP address ranges.
# schema:
#   type: object
#   properties:
#     blacklist:
#       type: array
#       title: "CIDR IP addresses (Example: 172.17.0.0/16)"
#       description: Prohibited IP address ranges
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - blacklist

deny_egress_ip_block_in_blacklist[reason] {
	# all egress traffic allowed
	count(parameters.blacklist) > 0
	network_policy_allows_all_egress
	reason := sprintf("%v allows access to any IP address.", [utils.input_id])
}

deny_egress_ip_block_in_blacklist[reason] {
	count(parameters.blacklist) > 0

	# fail if any IP ingress source is in one of the blacklisted CIDRs
	input.request.kind.kind == "NetworkPolicy"
	input.request.object.spec.policyTypes[_] == "Egress"
	ipBlock := input.request.object.spec.egress[_].to[_].ipBlock
	cidr := parameters.blacklist[_]
	net.cidr_intersects(cidr, ipBlock.cidr)
	not ip_range_excluded(ipBlock, cidr)
	reason := sprintf("%v allows egress traffic to the blacklisted range %v.", [utils.input_id, cidr])
}

network_policy_allows_all_egress {
	input.request.kind.kind == "NetworkPolicy"
	input.request.object.spec.policyTypes[_] == "Egress"
	egress := input.request.object.spec.egress[_]
	not egress.to
}

ip_range_excluded(ipBlock, range) {
	except := ipBlock.except[_]
	net.cidr_contains(except, range)
}

# regal ignore:custom-in-construct
in(ipBlock, ipBlocks) {
	ipBlock == ipBlocks[_]
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Restrict IP Blocks"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require `NetworkPolicy` resources to define ingress rules that only allow traffic within
#   the IP address ranges you specify.
# suggestions:
#   schema: network_policies_all_ingress_cidrs
# schema:
#   type: object
#   properties:
#     whitelist:
#       type: array
#       title: "CIDR IP addresses (Example: 172.17.0.0/16)"
#       description: Approved IP address ranges
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - whitelist

deny_ingress_ip_block_not_in_whitelist[reason] {
	# all ingress traffic allowed
	network_policy_allows_all_ingress
	reason := sprintf("%v allows access from any IP address.", [utils.input_id])
}

deny_ingress_ip_block_not_in_whitelist[reason] {
	count(parameters.whitelist) > 0

	# fail if any IP ingress source is not contained in one of the allowed CIDRs
	input.request.kind.kind == "NetworkPolicy"
	input.request.object.spec.policyTypes[_] == "Ingress"
	ipBlock := input.request.object.spec.ingress[_].from[_].ipBlock
	not any({t | t = net.cidr_contains(parameters.whitelist[_], ipBlock.cidr)})
	reason := sprintf("%v allows access from outside of allowed IP ranges.", [utils.input_id])
}

network_policies_all_ingress_cidrs["whitelist"] = arr {
	arr = {x |
		data.library.v1.kubernetes.monitor.v2.namespaced_objects_kind[["networkpolicies", resource, params]]
		resource.kind == "NetworkPolicy"
		resource.spec.policyTypes[_] == "Ingress"
		x = resource.spec.ingress[_].from[_].ipBlock.cidr
	}
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Prohibit IP Blocks"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Prevent `NetworkPolicy` resources from defining any ingress rules that allow traffic
#   on IP addresses in the prohibited ranges you specify.
# schema:
#   type: object
#   properties:
#     blacklist:
#       type: array
#       title: "CIDR IP addresses (Example: 172.17.0.0/16)"
#       description: Prohibited IP address ranges
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - blacklist

deny_ingress_ip_block_in_blacklist[reason] {
	# all ingress traffic allowed
	count(parameters.blacklist) > 0
	network_policy_allows_all_ingress
	reason := sprintf("%v allows access from any IP address.", [utils.input_id])
}

deny_ingress_ip_block_in_blacklist[reason] {
	count(parameters.blacklist) > 0

	# fail if any IP ingress source is in one of the blacklisted CIDRs
	input.request.kind.kind == "NetworkPolicy"
	input.request.object.spec.policyTypes[_] == "Ingress"
	ipBlock := input.request.object.spec.ingress[_].from[_].ipBlock
	cidr := parameters.blacklist[_]
	net.cidr_intersects(cidr, ipBlock.cidr)
	not ip_range_excluded(ipBlock, cidr)
	reason := sprintf("%v allows ingress traffic from the blacklisted range.", [utils.input_id])
}

network_policy_allows_all_ingress {
	input.request.kind.kind == "NetworkPolicy"
	input.request.object.spec.policyTypes[_] == "Ingress"
	ingress := input.request.object.spec.ingress[_]
	not ingress.from
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Prohibit Host Conflicts"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: Ensure that no two ingresses are configured to use the same hostname. This rule is not compatible with mock OPAs.

ingress_host_conflict[reason] {
	input.request.kind.kind == "Ingress"

	# find existing ingress not identical to 'input'
	existing := data.kubernetes.resources.ingresses[ns][name]
	[name, ns] != [input.request.object.metadata.name, input.request.object.metadata.namespace]

	# find rule in 'input' and rule in 'existing' with the same host
	host := input.request.object.spec.rules[_].host
	host == existing.spec.rules[_].host
	reason := sprintf("%v host %v conflicts with ingress %v/%v).", [utils.input_id, host, ns, name])
}

ingress_host_conflict[reason] {
	ingress_nohost_conflict[msg]
	reason = sprintf("%s (hostname conflict)", [msg])
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Prohibit Host Path Conflicts"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Ensure that no two ingresses are configured to use the same hostname and
#   overlapping paths. Path conflicts are detected using prefix matching. This rule is not compatible with mock OPAs.
# suggestions:

ingress_hostpath_conflict[reason] {
	input.request.kind.kind == "Ingress"

	# find existing ingress not identical to 'input'
	existing := data.kubernetes.resources.ingresses[ns][name]
	[name, ns] != [input.request.object.metadata.name, input.request.object.metadata.namespace]

	# grab mapping of host to paths for input and existing
	new_host_to_path := ingress_host_to_paths(input.request.object.spec.rules)
	old_host_to_path := ingress_host_to_paths(existing.spec.rules)

	# check if any of the host/paths conflict
	new_host_to_path[host]
	paths_conflict_prefix(new_host_to_path[host], old_host_to_path[host])
	reason := sprintf("%v host %v conflicts with ingress %v/%v).", [utils.input_id, host, ns, name])
}

# New ingress rule has missing host or existing ingress has missing host
ingress_hostpath_conflict[reason] {
	ingress_nohost_conflict[msg]
	reason = sprintf("%s (host path conflict)", [msg])
}

# given a set of ingress rules, compute a dictionary mapping a hostname to the set of paths
#   for that hostname (across all the rules)
ingress_host_to_paths(rules) = r {
	r := {rule.host: allpaths |
		rule := rules[_]
		allpaths := {p.path |
			rule2 := rules[_]
			rule2.host == rule.host
			p := rule2.http.paths[_]
		}
	}
}
