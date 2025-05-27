package library.v1.kubernetes.admission.metadata.v1

import data.library.parameters
import data.library.v1.kubernetes.admission.util.v1 as util
import data.library.v1.kubernetes.utils.v1 as utils

# Note: TODO: Build separate policy snippets for templates within specs.

# METADATA: library-snippet
# version: v1
# title: "Resources: Require Labels"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "metadata"
# description: >-
#   Resources must include metadata labels specified as key-value pairs. This rule does not apply
#   to labels in templates.
# resources:
#   exclusions:
#     - Namespace
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet
#     - Job
#     - DaemonSet
#     - Ingress
# schema:
#   type: object
#   properties:
#     required:
#       type: object
#       title: Label
#       patternNames:
#         title: "Key (Example: costcenter)"
#       additionalProperties:
#         type: array
#         title: "Values (Example: retail)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - required

missing_label[reason] {
	not utils.kind_matches({"Namespace"})

	# label is just missing
	parameters.required[key]
	not input.request.object.metadata.labels[key]
	reason := sprintf("Resource %v is missing required label %v.", [utils.input_id, key])
}

missing_label[reason] {
	not utils.kind_matches({"Namespace"})

	# label exists but has improper value
	possible_values := parameters.required[key]
	count(possible_values) > 0
	value := input.request.object.metadata.labels[key]
	not possible_values[value]
	reason := sprintf("Resource %v uses the prohibited label `%v: %v`.", [utils.input_id, key, value])
}

# METADATA: library-snippet
# version: v1
# title: "Resources: Require Pod Labels"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "metadata"
# description: >-
#   All pods must include metadata labels specified as key-value pairs.
# resources:
#   exclusions:
#     - Namespace
#   verifications:
#     - StatefulSet
#     - Deployment
#     - ReplicaSet
#     - DaemonSet
# schema:
#   type: object
#   properties:
#     labels:
#       type: object
#       title: Label
#       patternNames:
#         title: "Key (Example: costcenter)"
#       additionalProperties:
#         type: array
#         title: "Values (Example: retail)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - labels

template_pod_missing_label[reason] {
	not utils.kind_matches({"Namespace"})
	input.request.object.spec.template

	# label is just missing
	parameters.labels[key]
	not input.request.object.spec.template.metadata.labels[key]
	reason := sprintf("Pods in resource %v are missing required label %v.", [utils.input_id, key])
}

template_pod_missing_label[reason] {
	not utils.kind_matches({"Namespace"})
	input.request.object.spec.template

	# label exists but has improper value
	possible_values := parameters.labels[key]
	count(possible_values) > 0
	value := input.request.object.spec.template.metadata.labels[key]
	not possible_values[value]
	reason := sprintf("Pods in resource %v use the prohibited label `%v: %v`.", [utils.input_id, key, value])
}

# METADATA: library-snippet
# version: v1
# flag:
#   pre-release
# title: "Pods: Require Exclusive Use of Labels"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "metadata"
# tags:
#   pci_dss__v_3_2__1_1: "PCI DSS v3.2 1.1"
# description: >-
#   Require each pod to use one label from a mutually exclusive set of labels. For example,
#   you might define `priority: high` and `priority: low` as mutually-exclusive labels.
pod_fails_to_match_exactly_one_label[reason] {
	input.request.kind.kind == "Pod"
	actual_tier_labels := {k | input.request.object.metadata.labels[k]}
	used := actual_tier_labels & parameters.required
	count(used) != 1
	reason := sprintf("Every pod must be labeled with exactly one label. Number of labels found %s.", [used])
}

# METADATA: library-snippet
# version: v1
# title: "Resources: Require Annotations"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "metadata"
# description: >-
#   Resources must include specified annotations. This rule does not apply to
#   annotations inside of templates.
# resources:
#   exclusions:
#     - Namespace
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet
#     - Job
#     - DaemonSet
#     - Ingress
# schema:
#   type: object
#   properties:
#     required:
#       type: object
#       title: Annotation
#       patternNames:
#         title: "Key (Example: kubernetes.io/ingress.class)"
#       additionalProperties:
#         type: array
#         title: "Values (Example: nginx)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - required

missing_annotation[reason] {
	not utils.kind_matches({"Namespace"})

	# annotation is just missing
	parameters.required[key]
	not input.request.object.metadata.annotations[key]
	reason := sprintf("Resource %v is missing required annotation %v.", [utils.input_id, key])
}

missing_annotation[reason] {
	not utils.kind_matches({"Namespace"})

	# annotation exists but has improper value
	possible_values := parameters.required[key]
	count(possible_values) > 0
	value := input.request.object.metadata.annotations[key]
	not possible_values[value]
	reason := sprintf("Resource %v uses the prohibited annotation `%v: %v`.", [utils.input_id, key, value])
}

# METADATA: library-snippet
# version: v1
# title: "Namespaces: Restrict Names"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "metadata"
# description: >-
#   Namespace names must match one of the specified regular expressions.
# schema:
#   type: object
#   properties:
#     approved_names:
#       type: array
#       title: "Expressions (Example: ^(?:backend|frontend)-\\S+$)"
#       description: >-
#       items:
#         type: string
#         format: regex
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_names

invalid_naming_convention_namespace[reason] {
	count(parameters.approved_names) > 0
	utils.kind_matches({"Namespace"})
	util.modify_ops[input.request.operation]

	# naming convention not followed
	name := input.request.object.metadata.name
	not utils.name_matches_any(name, parameters.approved_names)
	reason := sprintf("Namespace %v does not match any valid naming convention.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Resources: Restrict Names"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "metadata"
# description: >-
#   Resource names must match one of the list of regular expressions. This rule does not
#   apply to names inside of templates.
# resources:
#   exclusions:
#     - Namespace
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet
#     - Job
#     - DaemonSet
#     - Ingress
# schema:
#   type: object
#   properties:
#     required:
#       type: array
#       title: "Expressions (Example: ^(?:backend|frontend)-\\S+)"
#       description: >-
#       items:
#         type: string
#         format: regex
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - required

invalid_naming_convention[reason] {
	not utils.kind_matches({"Namespace"})

	# naming convention not followed
	name := input.request.object.metadata.name
	not utils.name_matches_any(name, parameters.required)
	reason := sprintf("Resource %v does not match any valid naming convention.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Configmaps: Restrict nginx ingress configmap with snippet annotations allowed."
# severity: "medium"
# platform: "kubernetes"
# resource-type: "metadata"
# description: >-
#   Prevent Nginx Ingress configmaps with `allow-snippet-annotations` as `true`.
#   In multi-tenant clusters, a custom snippet annotation can be used by people with limited
#   permissions to retrieve clusterwide secrets.

deny_nginx_ingress_configmap_with_snippet_annotation_enabled[reason] {
	input.request.kind.kind == "ConfigMap"
	input.request.object.metadata.name == "ingress-nginx-controller"
	annotations_snippet := "allow-snippet-annotations"
	not input.request.object.data[annotations_snippet]
	reason := "Configmap ingress-nginx-controller does not have 'allow-snippet-annotations' specified in data."
}

deny_nginx_ingress_configmap_with_snippet_annotation_enabled[reason] {
	input.request.kind.kind == "ConfigMap"
	annotations_snippet := "allow-snippet-annotations"
	snippet_value := input.request.object.data[annotations_snippet]
	snippet_value == "true"
	reason := sprintf("Configmap '%v' has 'allow-snippet-annotations' specified as 'true' in data.", [input.request.name])
}
