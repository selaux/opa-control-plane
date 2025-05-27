package library.v1.kubernetes.utils.v1

# ------------------------------------------------------------------------------
# Human-friendly identifiers for `input`. Will always succeed.

input_id = id {
	id := sprintf("%v/%v/%v", [
		input_kind,
		input_namespace,
		input_name,
	])
}

kind_matches(set_of_kinds) {
	set_of_kinds[input.request.kind.kind]
}

name_matches_any(name, patterns) {
	pattern := patterns[_]
	regex.match(pattern, name)
}

input_labels = x {
	x := input.request.object.metadata.labels
} else = {}

input_annotations = x {
	x := input.request.object.metadata.annotations
} else = {}

input_name = x {
	x := input.request.object.metadata.name
}

else = x {
	x := "unknownName"
}

input_namespace = x {
	x := input.request.object.metadata.namespace
}

else = x {
	x := input.request.namespace
}

else = x {
	x := "unknownNS"
}

input_kind = x {
	x := input.request.kind.kind
}

else = x {
	x := "unknownKind"
}

# ----------------------------------------
# Resource name to kind translation helper

resource_name_to_kind["priorityclasses"] = "PriorityClass"

resource_name_to_kind["persistentvolumeclaims"] = "PersistentVolumeClaim"

resource_name_to_kind["componentstatuses"] = "ComponentStatus"

resource_name_to_kind["prometheusrules"] = "PrometheusRule"

resource_name_to_kind["horizontalpodautoscalers"] = "HorizontalPodAutoscaler"

resource_name_to_kind["mutatingwebhookconfigurations"] = "MutatingWebhookConfiguration"

resource_name_to_kind["cronjobs"] = "CronJob"

resource_name_to_kind["selfsubjectaccessreviews"] = "SelfSubjectAccessReview"

resource_name_to_kind["ingresses"] = "Ingress"

resource_name_to_kind["bindings"] = "Binding"

resource_name_to_kind["networkpolicies"] = "NetworkPolicy"

resource_name_to_kind["configmaps"] = "ConfigMap"

resource_name_to_kind["certificatesigningrequests"] = "CertificateSigningRequest"

resource_name_to_kind["apiservices"] = "APIService"

resource_name_to_kind["persistentvolumes"] = "PersistentVolume"

resource_name_to_kind["rolebindings"] = "RoleBinding"

resource_name_to_kind["deployments"] = "Deployment"

resource_name_to_kind["alertmanagers"] = "Alertmanager"

resource_name_to_kind["podtemplates"] = "PodTemplate"

resource_name_to_kind["storageclasses"] = "StorageClass"

resource_name_to_kind["nodes"] = "Node"

resource_name_to_kind["events"] = "Event"

resource_name_to_kind["servicemonitors"] = "ServiceMonitor"

resource_name_to_kind["jobs"] = "Job"

resource_name_to_kind["subjectaccessreviews"] = "SubjectAccessReview"

resource_name_to_kind["replicationcontrollers"] = "ReplicationControllerDummy"

resource_name_to_kind["controllerrevisions"] = "ControllerRevision"

resource_name_to_kind["limitranges"] = "LimitRange"

resource_name_to_kind["localsubjectaccessreviews"] = "LocalSubjectAccessReview"

resource_name_to_kind["namespaces"] = "Namespace"

resource_name_to_kind["workflows"] = "Workflow"

resource_name_to_kind["services"] = "Service"

resource_name_to_kind["clusterrolebindings"] = "ClusterRoleBinding"

resource_name_to_kind["resourcequotas"] = "ResourceQuota"

resource_name_to_kind["roles"] = "Role"

resource_name_to_kind["podsecuritypolicies"] = "PodSecurityPolicy"

resource_name_to_kind["statefulsets"] = "StatefulSet"

resource_name_to_kind["secrets"] = "Secret"

resource_name_to_kind["replicasets"] = "ReplicaSet"

resource_name_to_kind["poddisruptionbudgets"] = "PodDisruptionBudget"

resource_name_to_kind["daemonsets"] = "DaemonSet"

resource_name_to_kind["tokenreviews"] = "TokenReview"

resource_name_to_kind["volumeattachments"] = "VolumeAttachment"

resource_name_to_kind["validatingwebhookconfigurations"] = "ValidatingWebhookConfiguration"

resource_name_to_kind["prometheuses"] = "Prometheus"

resource_name_to_kind["selfsubjectrulesreviews"] = "SelfSubjectRulesReview"

resource_name_to_kind["serviceaccounts"] = "ServiceAccount"

resource_name_to_kind["endpoints"] = "Endpoints"

resource_name_to_kind["pods"] = "Pod"

resource_name_to_kind["clusterroles"] = "ClusterRole"

resource_name_to_kind["customresourcedefinitions"] = "CustomResourceDefinition"

resource_name_to_kind["*"] = "*"

resource_name_to_kind["validatingwebhookconfiguration"] = "ValidatingWebhookConfiguration"

resource_name_to_kind["mutatingwebhookconfiguration"] = "MutatingWebhookConfiguration"

# get_resource_kind resources the kind from the parameters if present and otherwise
# uses the resource_name_to_kind map to translate a plural k8s resource kind into its
# proper form. This is needed because the v1 monitoring policy does not put the kind
# into the params, while the v2 monitor policy does. Additionally, the
# admission_with_namespace method needs to maintain backward compatibility for potential
# use outside of the monitor policy.
get_resource_kind(params) = kind {
	kind := params.kind
} else = resource_name_to_kind[params.pluralkind]

# ------------------------------------------------------------------------------
# Helper for translating a resource into an admission control request

admission_with_namespace(obj, params) = x {
	namespace := params.namespace
	op := params.operation
	name := params.name
	username := params.username
	x := {
		"apiVersion": "v1",
		"request": {
			"kind": {"kind": get_resource_kind(params)},
			"operation": op,
			"namespace": namespace,
			"object": obj,
			"userInfo": {"username": username},
		},
	}
}

admission_no_namespace(obj, params) = x {
	# non-namespaced, pluralkind version
	op := params.operation
	name := params.name
	username := params.username
	x := {
		"apiVersion": "v1",
		"request": {
			"kind": {"kind": get_resource_kind(params)},
			"operation": op,
			"object": obj,
			"userInfo": {"username": username},
		},
	}
}

# ------------------------------------------------------------------------------
# Filters

# deprecated, use input_includes_key instead
input_includes_kinds(requirements) {
	input_includes_key("kinds", input_kind, requirements)
}

# deprecated, use input_includes_key instead
input_includes_namespaces(requirements) {
	input_includes_key("namespaces", input_namespace, requirements)
}

# deprecated, use input_includes instead
input_includes_labels(requirements) {
	input_includes("labels", input_labels, requirements)
}

# deprecated, use input_includes instead
input_includes_annotations(requirements) {
	input_includes("annotations", input_annotations, requirements)
}

# Returns `true` if `requirements[key]` isn’t defined, is empty, or has an
# entry matching `input_value`.
input_includes_key(key, input_value, requirements) {
	not requirements[key] == requirements[key]
}

else {
	count(requirements[key]) == 0
}

else {
	requirements[key][input_value]
}

else {
	contains_glob_match(key, input_value, requirements)
}

else {
	# WORKAROUND: https://styrainc.atlassian.net/browse/STY-3569
	count(requirements[key]) == 1
	requirements[key] == {""}
}

# Returns `true` if `requirements[key]` is defined AND does not contain an
# entry matching `input_value`.
input_excludes_key(key, input_value, requirements) {
	not contains_glob_match(key, input_value, requirements)
}

# input_includes returns true if the input_val is found in the requirements object and key field_name
input_includes(field_name, input_val, requirements) {
	data.library.v1.utils.labels.match.v1.includes_some(input_val, requirements[field_name])
} else {
	requirements_undefined(requirements, field_name)
}

# input_excludes returns true if the input_val is not found in the requirements object and key field_name
input_excludes(field_name, input_val, requirements) {
	data.library.v1.utils.labels.match.v1.includes_none(input_val, requirements[field_name])
} else {
	requirements_undefined(requirements, field_name)
}

requirements_undefined(requirements, field_name) {
	# field is undefined in the requirements object
	not requirements[field_name] == requirements[field_name]
} else {
	# field is defined as an empty set
	count(requirements[field_name]) == 0
} else {
	# WORKAROUND: https://styrainc.atlassian.net/browse/STY-3577
	requirements[field_name] == {"": set()}
} else = false

# Characters used to constrain wildcard matching.
delimiters = ["-", ".", "_"]

# contains_glob_match checks if the `input_value` matches any pattern contained in `requirements[key]`
contains_glob_match(key, input_value, requirements) {
	x := requirements[key][_]
	glob.match(x, delimiters, input_value)
}

# Returns `true` if `requirements` defines any of `kinds`, `labels`, or
# `namespaces` properties and corresponding matches are found (e.g., if `labels`
# is defined, at least one input label must match in `labels`).
#
# Use it to scope a rule to a subset of resources:
#
#   enforce[decision] {
#     include := {
#       "kinds": {
#         "Deployment",
#         "Service",
#         "StatefulSet"
#       }
#     }
#
#     data.library.v1.kubernetes.utils.v1.input_includes_requirements(include)
#
#     ...
#   }
input_includes_requirements(requirements) {
	input_includes_key("kinds", input_kind, requirements)
	input_includes_key("namespaces", input_namespace, requirements)
	input_includes("labels", input_labels, requirements)
	input_includes("annotations", input_annotations, requirements)
}

# input_excludes_requirements returns true if requirements defines
# kinds, labels, annotations, namespaces that are not in the input document.
# For each requirement field, this returns true when none of the values
# in the requirement set are found in the input.
# Intended to be used in snippets, e.g.,
#   enforce[decision] {
#     exclude := {
#       "kinds": {
#         "Deployment",
#         "Service",
#         "StatefulSet"
#       }
#     }
#
#     data.library.v1.kubernetes.utils.v1.input_excludes_requirements(exclude)
#
#     ...
#   }
input_excludes_requirements(requirements) {
	input_excludes_key("kinds", input_kind, requirements)
	input_excludes_key("namespaces", input_namespace, requirements)
	input_excludes("labels", input_labels, requirements)
	input_excludes("annotations", input_annotations, requirements)
}

# helper method to remain backwards compatible with the legacy rules style

get_decision_message(decision) = message {
	is_string(decision)
	message := decision
}

get_decision_message(decision) = message {
	not is_string(decision)
	not decision.allowed
	message := decision.message
}

get_decision_message(decision) = message {
	# decision.message is undefined... add something here so that
	# the violation is still reported, but doesn't have a message
	not is_string(decision)
	not decision.allowed
	not decision.message
	message := "undefined"
}

# decision_not_allowed provides backwards compatibility with string style deny messages
decision_not_allowed(decision) {
	decision.allowed == false
}

decision_not_allowed(decision) {
	is_string(decision)
}

get_object(request) = result {
	request.kind.kind = "Pod"
	result := request.object
}

get_object(request) = result {
	request.kind.kind = resources_with_pods[_]
	result := request.object.spec.template
}

# ------- Input helpers

resources_with_containers = {"Pod"} | resources_with_pods

resources_with_pods = {
	"Deployment",
	"DaemonSet",
	"ReplicaSet",
	"StatefulSet",
	"Job",
	"CronJob",
}

input_all_container[c] {
	c := input_regular_container[_]
}

input_all_container[c] {
	c := input_init_container[_]
}

# containers from pods
input_regular_container[c] {
	c := input.request.object.spec.containers[_]
}

# containers from other resource types
input_regular_container[c] {
	c := input.request.object.spec.template.spec.containers[_]
}

# initContainers from pods
input_init_container[c] {
	c := input.request.object.spec.initContainers[_]
}

# initContainers from all other resource types
input_init_container[c] {
	c := input.request.object.spec.template.spec.initContainers[_]
}

input_all_volumes[v] {
	v := input.request.object.spec.volumes[_]
}

input_all_volumes[v] {
	v := input.request.object.spec.template.spec.volumes[_]
}

# ------- CPU to number

cpu_to_number(cpu) = num {
	only_digits(cpu)
	num := to_number(cpu)
}

cpu_to_number(cpu) = num {
	num := milli_cpu_to_number(cpu)
}

# Handle fractional cpu unit case.
milli_cpu_to_number(s) = num {
	fraction_string(s)
	num := to_number(fraction_string(s))
}

# Handle millicpu unit case.
milli_cpu_to_number(s) = milli_cpu_string_to_number(s)

fraction_string(s) = s {
	regex.match(`\d+$\.\d+$`, s)
}

only_digits(s) = s {
	regex.match(`^[\d\.]+$`, s)
}

milli_cpu_string_to_number(s) = n {
	regex.match(`[1-9]\d*m`, s)
	m := to_number(substring(s, 0, count(s) - 1))
	n := m / 1000
}

# -------Memory to number

unit_K := 1000

unit_M := 1000 * unit_K

unit_G := 1000 * unit_M

unit_T := 1000 * unit_G

unit_P := 1000 * unit_T

unit_E := 1000 * unit_P

unit_Ki := 1024

unit_Mi := 1024 * unit_Ki

unit_Gi := 1024 * unit_Mi

unit_Ti := 1024 * unit_Gi

unit_Pi := 1024 * unit_Ti

unit_Ei := 1024 * unit_Pi

unit_table["K"] = unit_K

unit_table["M"] = unit_M

unit_table["G"] = unit_G

unit_table["T"] = unit_T

unit_table["P"] = unit_P

unit_table["E"] = unit_E

unit_table["Ki"] = unit_Ki

unit_table["Mi"] = unit_Mi

unit_table["Gi"] = unit_Gi

unit_table["Ti"] = unit_Ti

unit_table["Pi"] = unit_Pi

unit_table["Ei"] = unit_Ei

pow2_string_to_number(s) = n {
	# Note: units.parse_bytes does not work, see https://github.com/open-policy-agent/opa/issues/2340
	# instead just use regex to match <POSITIVE_INTEGER><UNIT> pattern. Then use unit table defined
	# below to convert into absolute number of bytes.
	#
	# This assignment just pattern-matches on the regex function result (which is an array of arrays...)
	[[_, num_str, unit]] := regex.find_all_string_submatch_n(`([1-9]\d*)([KMGTPE]i?)`, s, 1)

	# Convert to absolute number.
	n := to_number(num_str) * unit_table[unit]
}

pow2_string_to_number(s) = n {
	only_digits(s)
	n := to_number(s)
}

value_in_ranges(value, ranges) {
	range := ranges[_]
	minmax := split(range, "-")
	min := to_number(minmax[0])
	max := to_number(minmax[1])
	value >= min
	value <= max
}
