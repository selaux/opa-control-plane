package library.v1.kubernetes.admission.network.v1

import data.library.parameters
import data.library.v1.kubernetes.admission.util.v1 as util
import data.library.v1.kubernetes.admission.workload.v1 as workload
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Egresses: Restrict Selectors"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require `NetworkPolicy` resources to define egress rules with approved namespace and pod selectors.
# schema:
#   type: object
#   properties:
#     approved_namespace_selectors:
#       type: object
#       title: Allowed namespace selector labels
#       patternNames:
#         title: "Exact key (Example: environment)"
#       additionalProperties:
#         type: array
#         title: "Glob values (Example: test or dev-*)"
#         items:
#           type: string
#         uniqueItems: true
#     approved_pod_selectors:
#       type: object
#       title: Allowed pod selector labels
#       patternNames:
#         title: "Exact key (Example: role)"
#       additionalProperties:
#         type: array
#         title: "Glob values (Example: qa or dev-*)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_namespace_selectors
#     - approved_pod_selectors

netpol_egress_label_selector_whitelist[reason] {
	count(parameters.approved_namespace_selectors) > 0
	util.is_network_policy
	selector := input.request.object.spec.egress[_].to[_].namespaceSelector
	not util.selector_match(parameters.approved_namespace_selectors, selector)
	reason := sprintf("Egress uses invalid namespace selectors by network policy: %v .", [utils.input_id])
}

netpol_egress_label_selector_whitelist[reason] {
	count(parameters.approved_pod_selectors) > 0
	util.is_network_policy
	selector := input.request.object.spec.egress[_].to[_].podSelector
	not util.selector_match(parameters.approved_pod_selectors, selector)
	reason := sprintf("Egress uses invalid pod selectors by network policy: %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Egresses: Prohibit Namespace Selectors"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Prevent `NetworkPolicy` resources from defining any egress rules with
#   prohibited namespace selectors.
# schema:
#   type: object
#   properties:
#     prohibited_namespace_selectors:
#       type: object
#       title: Prohibited labels
#       patternNames:
#         title: "Exact key (Example: stage)"
#       additionalProperties:
#         type: array
#         title: "Glob values (Example: production or team-*)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_namespace_selectors

netpol_egress_entity_src_namespace_not_in_blacklist[reason] {
	count(parameters.prohibited_namespace_selectors) > 0
	util.is_network_policy
	selector := input.request.object.spec.egress[_].to[_].namespaceSelector
	util.selector_blacklist_match(parameters.prohibited_namespace_selectors, selector)
	reason := sprintf("Egress uses prohibited namespace selectors by network policy: %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Egresses: Restrict Ports"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Expect every egress `ports` field to match the specified
#   list of protocol-port pairs.
# schema:
#   type: object
#   properties:
#     approved_ports:
#       type: object
#       title: Allowed protocol and port pairs
#       patternNames:
#         title: "Protocol (Example: TCP)"
#       additionalProperties:
#         type: array
#         title: "Port (Example: 2222)"
#         items:
#           type: number
#         uniqueItems: true
#     approved_named_ports:
#       type: object
#       title: Allowed protocol and port pairs
#       patternNames:
#         title: "Protocol (Example: TCP)"
#       additionalProperties:
#         type: array
#         title: "Named port (Example: metric)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_ports
#     - approved_named_ports
#   hint:order:
#     - approved_ports
#     - approved_named_ports

netpol_egress_entity_src_port_whitelist[reason] {
	count(parameters.approved_ports) + count(parameters.approved_named_ports) > 0
	util.is_network_policy
	all_ports := input.request.object.spec.egress[_].ports
	not util.ports_in_whitelist(parameters.approved_ports, all_ports)
	not util.ports_in_whitelist(parameters.approved_named_ports, all_ports)
	reason := sprintf("Egress uses ports that are not whitelisted by network policy: %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Egresses: Prohibit Ports"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Prevent `NetworkPolicy` resources from defining any egress rules with
#   prohibited ports.
# schema:
#   type: object
#   properties:
#     prohibited_ports:
#       type: object
#       title: Prohibited protocol and port pairs
#       patternNames:
#         title: "Protocol (Example: TCP)"
#       additionalProperties:
#         type: array
#         title: "Port (Example: 2222)"
#         items:
#           type: number
#         uniqueItems: true
#     prohibited_named_ports:
#       type: object
#       title: Prohibited protocol and named port pairs
#       patternNames:
#         title: "Protocol (Example: TCP)"
#       additionalProperties:
#         type: array
#         title: "Named port (Example: metric)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_ports
#     - prohibited_named_ports
#   hint:order:
#     - prohibited_ports
#     - prohibited_named_ports

netpol_egress_entity_src_port_blacklist[reason] {
	count(parameters.prohibited_ports) > 0
	util.is_network_policy
	all_ports := input.request.object.spec.egress[_].ports
	util.ports_in_blacklist(parameters.prohibited_ports, all_ports)
	reason := sprintf("Egress uses ports that are blacklisted by network policy: %v.", [utils.input_id])
}

netpol_egress_entity_src_port_blacklist[reason] {
	count(parameters.prohibited_named_ports) > 0
	util.is_network_policy
	all_ports := input.request.object.spec.egress[_].ports
	util.ports_in_blacklist(parameters.prohibited_named_ports, all_ports)
	reason := sprintf("Egress uses ports that are blacklisted by network policy: %v.", [utils.input_id])
}

netpol_egress_entity_src_port_blacklist[reason] {
	count(parameters.prohibited_ports) > 0
	util.is_network_policy

	# If any of the port is not specified, then it means it matches all ports and numbers.
	# This should be reported as error in case of blacklist.
	single_port = input.request.object.spec.egress[_].ports[_]
	not single_port.port
	reason := sprintf("Egress uses ports that are blacklisted by network policy: %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Restrict Ports"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require every ingress `ports` field to match the list of specified
#   protocol-port pairs.
# schema:
#   type: object
#   properties:
#     approved_ports:
#       type: object
#       title: Allowed protocol and port pairs
#       patternNames:
#         title: "Protocol (Example: TCP)"
#       additionalProperties:
#         type: array
#         title: "Port (Example: 2222)"
#         items:
#           type: number
#         uniqueItems: true
#     approved_named_ports:
#       type: object
#       title: Allowed protocol and port pairs
#       patternNames:
#         title: "Protocol (Example: TCP)"
#       additionalProperties:
#         type: array
#         title: "Named port (Example: metric)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_ports
#     - approved_named_ports
#   hint:order:
#     - approved_ports
#     - approved_named_ports

netpol_ingress_entity_src_port_whitelist[reason] {
	count(parameters.approved_ports) + count(parameters.approved_named_ports) > 0
	util.is_network_policy
	all_ports := input.request.object.spec.ingress[_].ports
	not util.ports_in_whitelist(parameters.approved_ports, all_ports)
	not util.ports_in_whitelist(parameters.approved_named_ports, all_ports)
	reason := sprintf("Ingress uses ports that are not whitelisted by network policy: %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Prohibit Ports"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Prevent `NetworkPolicy` resources from defining any inbound (ingress) rules that
#   use prohibited ports.
# schema:
#   type: object
#   properties:
#     prohibited_ports:
#       type: object
#       title: Prohibited protocol and port pairs
#       patternNames:
#         title: "Protocol (Example: TCP)"
#       additionalProperties:
#         type: array
#         title: "Port (Example: 2222)"
#         items:
#           type: number
#         uniqueItems: true
#     prohibited_named_ports:
#       type: object
#       title: Prohibited protocol and named port pairs
#       patternNames:
#         title: "Protocol (Example: TCP)"
#       additionalProperties:
#         type: array
#         title: "Named Port (Example: metric)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_ports
#     - prohibited_named_ports
#   hint:order:
#     - prohibited_ports
#     - prohibited_named_ports

netpol_ingress_entity_src_port_blacklist[reason] {
	count(parameters.prohibited_ports) > 0
	util.is_network_policy
	all_ports := input.request.object.spec.ingress[_].ports
	util.ports_in_blacklist(parameters.prohibited_ports, all_ports)
	reason := sprintf("Ingress uses ports that are blacklisted by network policy: %v.", [utils.input_id])
}

netpol_ingress_entity_src_port_blacklist[reason] {
	count(parameters.prohibited_named_ports) > 0
	util.is_network_policy
	all_ports := input.request.object.spec.ingress[_].ports
	util.ports_in_blacklist(parameters.prohibited_named_ports, all_ports)
	reason := sprintf("Ingress uses ports that are blacklisted by network policy: %v.", [utils.input_id])
}

netpol_ingress_entity_src_port_blacklist[reason] {
	count(parameters.prohibited_ports) > 0
	util.is_network_policy

	# If any of the port is not specified, then it means it matches all ports and numbers.
	# This should be reported as error in case of blacklist.
	single_port = input.request.object.spec.ingress[_].ports[_]
	not single_port.port
	reason := sprintf("Ingress uses ports that are blacklisted by network policy: %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Restrict Namespace and Pod Selectors"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require `NetworkPolicy` resources define ingress rules that include approved namespace selectors
#   and pod selectors.
# schema:
#   type: object
#   properties:
#     approved_namespace_selectors:
#       type: object
#       title: Allowed namespace selector key-value pairs
#       patternNames:
#         title: "Exact key (Example: name)"
#       additionalProperties:
#         type: array
#         title: "Glob values (Example: team-*-development)"
#         items:
#           type: string
#         uniqueItems: true
#     approved_pod_selectors:
#       type: object
#       title: Allowed pod selector key-value pairs
#       patternNames:
#         title: "Exact key (Example: partition)"
#       additionalProperties:
#         type: array
#         title: "Glob values (Example: customer*)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_namespace_selectors
#     - approved_pod_selectors
#   hint:order:
#     - approved_namespace_selectors
#     - approved_pod_selectors

netpol_ingress_label_selector_whitelist[reason] {
	count(parameters.approved_namespace_selectors) > 0
	util.is_network_policy
	selector := input.request.object.spec.ingress[_].from[_].namespaceSelector
	not util.selector_match(parameters.approved_namespace_selectors, selector)
	reason := sprintf("Ingress uses invalid namespace selectors by network policy: %v.", [utils.input_id])
}

netpol_ingress_label_selector_whitelist[reason] {
	count(parameters.approved_pod_selectors) > 0
	util.is_network_policy
	selector := input.request.object.spec.ingress[_].from[_].podSelector
	not util.selector_match(parameters.approved_pod_selectors, selector)
	reason := sprintf("Ingress uses invalid pod selectors by network policy: %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Prohibit Namespace Selectors"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Prevent `NetworkPolicy` resources from defining any ingress rules with
#   prohibited namespace selectors.
# schema:
#   type: object
#   properties:
#     prohibited_namespace_selectors:
#       type: object
#       title: Prohibited Labels
#       patternNames:
#         title: "Exact key (Example: name)"
#       additionalProperties:
#         type: array
#         title: "Glob values (Example: team-*-development)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_namespace_selectors

netpol_ingress_entity_src_namespace_not_in_blacklist[reason] {
	count(parameters.prohibited_namespace_selectors) > 0
	util.is_network_policy
	selector := input.request.object.spec.ingress[_].from[_].namespaceSelector
	util.selector_blacklist_match(parameters.prohibited_namespace_selectors, selector)
	reason := sprintf("Ingress uses prohibited namespace selectors by network policy: %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Services: Prohibit External Load Balancers"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: Prevent services from creating cloud network load balancers.

restrict_external_lbs[reason] {
	input.request.kind.kind == "Service"
	util.is_create_or_update
	input.request.object.spec.type == "LoadBalancer"
	reason := sprintf("Service %v of type `LoadBalancer` is prohibited.", [input.request.object.metadata.name])
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Restrict Ingress with default Ingress-class."
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Ensure that every Ingress reource is created with an ingress-class other
#   than the default eg. use annotation `kubernetes.io/ingress.class: nginx-internal`.
deny_ingress_with_default_or_no_ingress_class[reason] {
	input.request.kind.kind == "Ingress"
	is_ingress_class_invalid(input.request.object)
	reason := sprintf("%v has no or invalid ingress-class.", [utils.input_id])
}

is_ingress_class_invalid(object) {
	not input.request.object.spec.ingressClassName
	not input.request.object.metadata.annotations["kubernetes.io/ingress.class"]
}

is_ingress_class_invalid(object) {
	object.spec.ingressClassName == ""
}

is_ingress_class_invalid(object) {
	object.metadata.annotations["kubernetes.io/ingress.class"] == ""
}

# METADATA: library-snippet
# version: v1
# title: "Services: Restrict IP Addresses"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require every service’s `clusterIP` address to be included in the
#   approved IP address range.
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

deny_cluster_ip_not_in_whitelist[reason] {
	overlapping_results := {out |
		cidr := parameters.whitelist[_]
		out := net.cidr_overlap(cidr, input.request.object.spec.clusterIP)
	}

	not any(overlapping_results)
	reason := sprintf("%v with IP %v is not included in the allowed list.", [utils.input_id, input.request.object.spec.clusterIP])
}

# METADATA: library-snippet
# version: v1
# title: "Services: Prohibit IP Addresses"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Prevent any service’s `clusterIP` address from being defined within a
#   prohibited IP range.
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

deny_cluster_ip_in_blacklist[reason] {
	count(parameters.blacklist) > 0
	net.cidr_overlap(parameters.blacklist[_], input.request.object.spec.clusterIP)
	reason := sprintf("%v with IP %v is a blacklisted IP address.", [utils.input_id, input.request.object.spec.clusterIP])
}

#######################################################
# Network Communication
#
# UNTESTED
# DISABLED_METADATA: library-snippet
# version: v1
# disabled: true # Not yet supported by data-driven UI.
# title: "Networking: Restrict Communication for Pods and Labels"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Ensure NetworkPolicies and Labels are configured so that the only incoming traffic
#   to the specified TO target is from the specified FROM target.
#
# Example
# parameters = {
#     "from": {"app"},
#     "to": {"dmz"},
# }

# prohibited_communication_pod_labels[reason] {
#     input.request.kind.kind == "Pod"
#     input_pod := fill_out_metadata(input.request.object)
#     other_pod := data.kubernetes.resources.pods[_][_]
#     tofrom := grab_to_anti_from(input_pod, other_pod)
#     msg := talks_to_explain(tofrom.from, tofrom.to)
#     count(msg) > 0
# 	reason := sprintf("%v can communicate with pod %v due to the configuration of `NetworkPolicy`: %v.",
#         [resource_id(tofrom.from), resource_id(tofrom.to), msg])
# }

# # return a binding for to/from that would violate the fact that ONLY FROMs can send to TOs
# grab_to_anti_from(pod1, pod2) = x {
#     matches_styra_label_selector(pod1, parameters.to)
#     not matches_styra_label_selector(pod2, parameters.from)
#     x := {"from": pod2, "to": pod1}
# }

# grab_to_anti_from(pod1, pod2) = x {
#     matches_styra_label_selector(pod2, parameters.to)
#     not matches_styra_label_selector(pod1, parameters.from)
#     x := {"from": pod1, "to": pod2}
# }

# UNTESTED
# DISABLED_METADATA: library-snippet
# version: v1
# disabled: true # Not yet supported by data-driven UI.
# title: "Networking: Prohibit Communication Between Pod Labels"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require `NetworkPolicies` and `Labels` to be configured so that two groups of pods
#   can be described by a label set.
#
# Example
# parameters = {
#     "from": {"app"},
#     "to": {"dmz"},
# }

prohibited_communication_pod_labels[reason] {
	input.request.kind.kind == "Pod"
	input_pod := fill_out_metadata(input.request.object)
	other_pod := data.kubernetes.resources.pods[_][_]
	tofrom := grab_to_from(input_pod, other_pod)
	msg := talks_to_explain(tofrom.from, tofrom.to)
	count(msg) > 0
	reason := sprintf("%v can communicate with pod %v due to the configuration of `NetworkPolicy`: %v.", [resource_id(tofrom.from), resource_id(tofrom.to), msg])
}

grab_to_from(pod1, pod2) = x {
	matches_styra_label_selector(pod1, parameters.to)
	matches_styra_label_selector(pod2, parameters.from)
	x := {"from": pod2, "to": pod1}
}

grab_to_from(pod1, pod2) = x {
	matches_styra_label_selector(pod1, parameters.from)
	matches_styra_label_selector(pod2, parameters.to)
	x := {"from": pod1, "to": pod2}
}

# matches_styra_label_selector checks if OBJ satisfies the description in SELECTOR.
# Currently SELECTOR is a set of label keys, since that is supported by the snippet UI
matches_styra_label_selector(obj, selector) {
	selector[key]
	obj.metadata.labels[key]
}

#######################################################
# Network Coverage
#

# METADATA: library-snippet
# version: v1
# disabled: true # Not yet supported by data-driven UI.
# title: "Container: Require Complete Network Policy Coverage for Pods"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require all pods to be controlled by a `NetworkPolicy` and reject any
#   pod that is not controlled by a `NetworkPolicy`.

# Case where pod changes
incomplete_network_coverage_pod[reason] {
	input.request.kind.kind == "Pod"
	obj := fill_out_metadata(input.request.object)
	not controlled_by_network_policy(obj)
	reason := sprintf("%s is not controlled by a `NetworkPolicy`.", [resource_id(input.request.object)])
}

# METADATA: library-snippet
# version: v1
# disabled: true # Not yet supported by data-driven UI.
# title: "Container: Require Complete Network Policy Coverage for Templated Pods"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require all pods to be controlled by a `NetworkPolicy` and reject any
#   template that produces a pod that is not controlled by a `NetworkPolicy`.

# Case where templated object changes
incomplete_network_coverage_template[reason] {
	# any templated object
	obj := fill_out_metadata_for_template(input.request.object.spec.template) # PodTemplate
	not controlled_by_network_policy(obj)
	reason := sprintf("Templated resource %s is not controlled by a `NetworkPolicy`.", [resource_id(input.request.object)])
}

# METADATA: library-snippet
# version: v1
# disabled: true # Not yet supported by data-driven UI.
# title: "Network: Require Complete Network Policy Coverage"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require all pods to be controlled by network policy and reject `NetworkingPolicy` changes
#   that leave pods without `NetworkingPolicy` coverage.
incomplete_network_coverage_networkpolicy[reason] {
	input.request.operation == "UPDATE"
	input.request.kind.kind == "NetworkPolicy"
	pod := data.kubernetes.resources.pods[_][_]
	np_namespace := input.request.namespace
	np_name := input.request.object.metadata.name
	not controlled_by_network_policy_except(pod, {"namespace": np_namespace, "name": np_name})
	not matches_podSelector(pod, input.request.object.spec.podSelector)
	reason := sprintf("Network policy change results in pod %s not being controlled by `NetworkPolicy`.", [resource_id(pod)])
}

incomplete_network_coverage_networkpolicy[reason] {
	input.request.operation == "DELETE"
	input.request.kind.kind == "NetworkPolicy"
	pod := data.kubernetes.resources.pods[_][_]
	np_namespace := input.request.namespace
	np_name := input.request.object.metadata.name
	not controlled_by_network_policy_except(pod, {"namespace": np_namespace, "name": np_name})
	reason := sprintf("NetworkPolicy change results in pod %s not being controlled by `NetworkPolicy`.", [resource_id(pod)])
}

# METADATA: library-snippet
# version: v1
# disabled: true # Not yet supported by data-driven UI.
# title: "Invariant: Require Complete Network Policy Coverage"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Require all pods to be controlled by network policy and reject any changes to
#   network policy, pods, and templated pods that violate the network policy.
incomplete_network_coverage_all[reason] {
	incomplete_network_coverage_pod[reason]
}

incomplete_network_coverage_all[reason] {
	incomplete_network_coverage_template[reason]
}

incomplete_network_coverage_all[reason] {
	incomplete_network_coverage_networkpolicy[reason]
}

#######################################################
# NetworkPolicy
# https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.14/#networkpolicy-v1-networking-k8s-io
# NetworkPolicySpec
# https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.14/#networkpolicyspec-v1-networking-k8s-io
# egress
# ingress
# podSelector
# policyTypes

controlled_by_network_policy(obj) {
	selector := data.kubernetes.resources.networkpolicies[_][_].spec.podSelector
	matches_podSelector(obj, selector)
}

controlled_by_network_policy_except(obj, netpolicyspec) {
	selector := data.kubernetes.resources.networkpolicies[namespace][name].spec.podSelector
	trace(sprintf("netpolicyspec: %s; namespace: %s; name: %s", [netpolicyspec, namespace, name]))
	[namespace, name] != [netpolicyspec.namespace, netpolicyspec.name]
	trace(sprintf("Checking match on namespace: %s; name: %s", [namespace, name]))
	matches_podSelector(obj, selector)
	trace(sprintf("Success for namespace: %s; name: %s", [namespace, name]))
}

# talks_to is true when obj1 can send traffic to obj2
talks_to(obj1, obj2) {
	not controlled_by_network_policy(obj2)
}

talks_to(obj1, obj2) {
	# some ns
	np := data.kubernetes.resources.networkpolicies[ns][name]
	matches_podSelector(obj2, np.spec.podSelector)
	ing := np.spec.ingress[_]
	matches_ingressSelector(obj1, ing, ns)
}

talks_to_explain(obj1, obj2) = msg {
	not controlled_by_network_policy(obj2)
	msg := sprintf("%s is not controlled by any network policy.", [obj2])
}

talks_to_explain(obj1, obj2) = msg {
	controlled_by_network_policy(obj2)
	all := {m |
		# some ns, name
		np := data.kubernetes.resources.networkpolicies[ns][name]
		matches_podSelector(obj2, np.spec.podSelector)

		# some i
		ing := np.spec.ingress[i]
		matches_ingressSelector(obj1, ing, ns)
		m := sprintf("%s/%s with ingress %s", [ns, name, i])
	}

	msg := concat(";", all)
}

#######################################################
# NetworkIngress describes permitted incoming traffic
# from: NetworkPolicyPeer array
# https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.14/#networkpolicyingressrule-v1-networking-k8s-io

matches_ingressSelector(pod, ingress, default_namespace) {
	not ingress.from # source does not matter
}

matches_ingressSelector(pod, ingress, default_namespace) {
	count(ingress.from) == 0 # as per spec: empty means match everything
}

matches_ingressSelector(pod, ingress, default_namespace) {
	matches_networkPeer(pod, ingress.from[_], default_namespace)
}

#######################################################
# NetworkPolicyPeer (peer) is a peer to allow traffic from/to
# https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.14/#networkpolicypeer-v1-networking-k8s-io
#
# disabled: true # Not yet supported by data-driven UI.
# Example:
# - ipBlock:
#     cidr: 172.17.0.0/16
#     except:
#     - 172.17.1.0/24
# - namespaceSelector:
#     matchLabels:
#         project: myproject
# - podSelector:
#     matchLabels:
#         role: frontend
#   namespaceSelector:
#     matchLabels:
#         project: yourproject

matches_networkPeer(pod, peer, default_namespace) {
	peer.ipBlock # pod IP are ephemeral; can't match a fixed IPBlock
	false
}

matches_networkPeer(pod, peer, default_namespace) {
	matches_podSelector(pod, peer.podSelector)
	matches_namespaceSelector(pod, peer.namespaceSelector)
}

matches_networkPeer(pod, peer, default_namespace) {
	not peer.podSelector
	matches_namespaceSelector(pod, peer.namespaceSelector)
}

matches_networkPeer(pod, peer, default_namespace) {
	not peer.namespaceSelector
	peer.podSelector
	pod.metadata.namespace == default_namespace
	matches_podSelector(pod, peer.podSelector)
}

#######################################################
# LabelSelectors
# Example:
#     matchLabels:
#       role: db
#     matchExpression:
#     - key: foo
#       operator: in
#       values: ["a", "b", "c"]

matches_podSelector(obj, selector) {
	matches_labelSelector(obj, selector)
}

matches_namespaceSelector(obj, selector) {
	ns := data.kubernetes.resources.namespaces[obj.metadata.namespace]
	matches_labelSelector(ns, selector)
}

matches_labelSelector(obj, selector) {
	selector != null # null label selector matches nothing
	selector_matchesExpressions(obj, selector)
	selector_matchesLabels(obj, selector)
}

selector_matchesExpressions(obj, selector) {
	not selector.matchExpressions
}

selector_matchesExpressions(obj, selector) {
	matchesExpressions(obj.metadata.labels, selector.matchExpressions)
}

selector_matchesLabels(obj, selector) {
	not selector.matchLabels
}

selector_matchesLabels(obj, selector) {
	matchesLabels(obj.metadata.labels, selector.matchLabels)
}

# matchExpressions is a list of LabelSelectorsRequirements:
#  A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#   key is the label key that the selector applies to.
#   operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
#   values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.

matchesExpressions(labels, matchExpressions) {
	not matchExpressions_fails(labels, matchExpressions)
}

matchExpressions_fails(labels, matchExpressions) {
	me := matchExpressions[_]
	not matchExpression(labels, me)
}

matchExpression(labels, me) {
	lower(me.operator) == "exists"
	labels[me.key]
}

matchExpression(labels, me) {
	lower(me.operator) == "doesnotexist"
	not labels[me.key]
}

matchExpression(labels, me) {
	lower(me.operator) == "in"
	me.values[_] == labels[me.key]
}

matchExpression(labels, me) {
	lower(me.operator) == "notin"
	found := {x | x := me.values[_]; labels[me.key] == x}
	count(found) == 0
}

#  matchLabels is a map of {key,value} pairs.
#  A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions,
#    whose key field is "key", the operator is "In", and the values array contains only "value".
#    The requirements are ANDed.
matchesLabels(labels, matchLabels) {
	not matchLabels_fails(labels, matchLabels)
}

matchLabels_fails(labels, matchLabels) {
	value := matchLabels[key]
	not labels[key] == value
}

# Fill in any missing metadata for 'obj' using the admission control 'input' (where obj is a PodTemplate)
#  Guarantees: namespace, name, labels
fill_out_metadata_for_template(obj) = newobj {
	non_metadata := util.reduce_object_blacklist(obj, {"metadata"})
	metadata_extra := util.reduce_object_blacklist(obj.metadata, {"namespace", "labels", "name"})
	metadata_ns := util.get(obj.metadata, "namespace", util.get(input.request, "namespace", "default"))
	metadata_name := util.get(obj.metadata, "name", util.get(input.request.object.metadata, "name", "cantfindname"))
	metadata_labels := util.get(obj.metadata, "labels", util.get(input.request.object.metadata, "labels", {}))
	metadata_new := util.merge_objects(metadata_extra, {"namespace": metadata_ns, "name": metadata_name, "labels": metadata_labels})
	newobj := util.merge_objects({"metadata": metadata_new}, non_metadata)
}

# Fill in any missing metadata for 'obj' using the admission control 'input'
fill_out_metadata(obj) = newobj {
	non_metadata := util.reduce_object_blacklist(obj, {"metadata"})
	metadata_extra := util.reduce_object_blacklist(obj.metadata, {"namespace"})
	metadata_ns := util.get(obj.metadata, "namespace", util.get(input.request, "namespace", "default"))
	metadata_new := util.merge_objects(metadata_extra, {"namespace": metadata_ns})
	newobj := util.merge_objects({"metadata": metadata_new}, non_metadata)
}

resource_id(obj) = id {
	id := sprintf("%v/%v/%v", [
		resource_kind(obj),
		resource_namespace(obj),
		resource_name(obj),
	])
}

resource_kind(obj) = x {
	x := obj.kind
}

else = "UnknownKind"

resource_namespace(obj) = x {
	x := obj.metadata.namespace
}

else = "UnknownNS"

resource_name(obj) = x {
	x := obj.metadata.name
}

else = "UnknownName"

# METADATA: library-snippet
# version: v1
# title: "Loadbalancer: Restrict loadBalancerSourceRanges"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   `Loadbalancer` resources should only allow traffic from the provided IP ranges.
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

deny_loadbalancersourceranges_not_in_whitelist[reason] {
	count(parameters.whitelist) > 0

	# fail if any loadBalancerSourceRanges is not contained in one of the allowed CIDRs
	input.request.kind.kind == "Service"
	input.request.object.spec.type == "LoadBalancer"
	ipBlock := input.request.object.spec.loadBalancerSourceRanges[_]
	not any({t | t = net.cidr_contains(parameters.whitelist[_], ipBlock)})
	reason := sprintf("%v allows access from outside of allowed IP ranges.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Loadbalancer: Prohibit loadBalancerSourceRanges"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   `Loadbalancer` resources must not allow traffic from the provided IP ranges.
# schema:
#   type: object
#   properties:
#     blacklist:
#       type: array
#       title: "CIDR IP addresses (Example: 172.17.0.0/16)"
#       description: Blacklisted IP address ranges
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - blacklist
deny_loadbalancersourceranges_in_blacklist[reason] {
	count(parameters.blacklist) > 0

	# fail if any loadBalancerSourceRanges is contained in one of the blacklisted CIDRs
	input.request.kind.kind == "Service"
	input.request.object.spec.type == "LoadBalancer"
	ipBlock := input.request.object.spec.loadBalancerSourceRanges[_]
	cidr := parameters.blacklist[_]
	net.cidr_intersects(cidr, ipBlock)
	reason := sprintf("%v allows access from blacklisted IP range.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Service: Restrict Ports"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Ensure services listen only on allowed ports.
# schema:
#   type: object
#   properties:
#     port_numbers:
#       type: array
#       title: "Port number(Example: 8080,5454)"
#       items:
#         type: string
#       uniqueItems: true
#   required:
#     - port_numbers
restricts_service_ports[reason] {
	count(parameters.port_numbers) > 0
	input.request.kind.kind == "Service"
	port := input.request.object.spec.ports[_].port
	not is_port_allowed(port, parameters.port_numbers)
	reason := sprintf("%v uses port %v which is not in allowed list", [utils.input_id, port])
}

is_port_allowed(port, allowed_ports) {
	p_port := allowed_ports[_]
	to_number(p_port) == port
}

# METADATA: library-snippet
# version: v1
# title: "Container: Restrict Ports"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Ensure containers listen only on allowed ports.
# schema:
#   type: object
#   properties:
#     container_port_numbers:
#       type: array
#       title: "Port number(Example: 8080,5454)"
#       items:
#         type: string
#       uniqueItems: true
#   required:
#     - container_port_numbers
restricts_container_ports[reason] {
	count(parameters.container_port_numbers) > 0
	containers := workload.input_all_container[_]
	port := containers.ports[_].containerPort
	not is_port_allowed(port, parameters.container_port_numbers)
	reason := sprintf("%v uses port %v which is not in allowed list", [utils.input_id, port])
}

# METADATA: library-snippet
# version: v1
# title: "kubectl exec: Restrict Commands"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#    Allows users to whitelist commands that may be used with “kubectl exec”
# schema:
#   type: object
#   properties:
#     allowed_commands:
#       type: array
#       title: "Commands that will be used with kubectl exec"
#       items:
#         type: string
#       uniqueItems: true
#   required:
#     - allowed_commands
whitelist_exec_commands[reason] {
	input.request.kind.kind == "PodExecOptions"
	input.request.object.command

	user := input.request.userInfo.username
	pod_id := input.request.name
	container := input.request.object.container
	command := input.request.object.command[_]
	not is_command_allowed(command, parameters.allowed_commands)
	reason := sprintf("Exec: User %s executed command \"%s\" on pod %s container %s which is not allowed", [user, command, pod_id, container])
}

is_command_allowed(command, allowed_commands) {
	cmd := allowed_commands[_]
	cmd == command
}

# METADATA: library-snippet
# version: v1
# title: "Ingresses: Deny custom snippet annotations."
# severity: "medium"
# platform: "kubernetes"
# resource-type: "network"
# description: >-
#   Prevent Ingress resources with a custom snippet annotation from being created or updated.
#   In multi-tenant clusters, a custom snippet annotation can be used by people with limited
#   permissions to retrieve clusterwide secrets.

deny_ingress_with_custom_snippet_annotation[reason] {
	input.request.kind.kind == "Ingress"
	some annotation
	input.request.object.metadata.annotations[annotation]
	contains(annotation, "-snippet")
	reason := sprintf("%s uses a custom snippet annotation '%v'.", [utils.input_id, annotation])
}
