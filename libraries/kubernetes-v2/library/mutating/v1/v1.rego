package library.v1.kubernetes.mutating.v1

import data.kubernetes.resources
import data.library.parameters
import data.library.v1.kubernetes.admission.workload.v1 as workload
import data.library.v1.kubernetes.utils.envoy.v1 as envoy_utils
import data.library.v1.kubernetes.utils.opa.v1 as opa_utils
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Inject OPA & Envoy sidecars into pod"
# description: >-
#  Injects an OPA sidecar to a Pod/Deployment template for objects labeled
#  with the specified label/value.  Will default to using the
#  "opa:latest-envoy-rootless" image unless channel overrides are included in
#  the mutation policy file.
# schema:
#   parameters:
#   - name: "channel"
#     label: "Channel"
#     type: string
#     items: ["Rapid", "Regular", "Stable"]
#     default: "Regular"
#   - name: "config"
#     label: "ConfigMap for OPA"
#     type: string
#     default: opa-envoy-config
#   - name: "config-envoy"
#     label: "ConfigMap for Envoy"
#     type: string
#     default: envoy-config
#   - name: "label"
#     label: "Label to check"
#     type: string
#     default: inject-opa
#   - name: "use-socket"
#     label: "Use Socket"
#     type: string
#     items: ["Yes", "No"]
#     default: "Yes"
#   - name: "label-value"
#     label: "Label value to check for"
#     type: string
#     default: enabled
#   decision:
#     - type: rego
#       key: patch
#       value: "patch"
#     - type: rego
#       key: message
#       value: "\"Adding OPA and Envoy sidecars & volumes\""
#     - type: rego
#       key: allowed
#       value: "true"
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[patch]"

envoy_and_opa_patches[patch] {
	opa_utils.injectable_object
	patch := array.concat(
		[
			envoy_utils.init_patch,
			envoy_utils.envoy_patch,
			opa_utils.opa_patch,
		],
		envoy_utils.opa_and_envoy_volume_patch,
	)
}

# METADATA: library-snippet
# version: v1
# title: "Inject OPA sidecar to Istio pod"
# description: >-
#  Injects an OPA sidecar to a Pod/Deployment template for objects labeled
#  with the specified label/value.  Will default to using the
#  "opa:latest-envoy-rootless" image unless channel overrides are included in
#  the mutation policy file.
# schema:
#   parameters:
#   - name: "channel"
#     label: "Channel"
#     type: string
#     items: ["Rapid", "Regular", "Stable"]
#     default: "Regular"
#   - name: "config"
#     label: "ConfigMap for OPA"
#     type: string
#     default: opa-istio-config
#   - name: "label"
#     label: "Label to check"
#     type: string
#     default: istio-injection
#   - name: "label-value"
#     label: "Label value to check for"
#     type: string
#     default: enabled
#   decision:
#     - type: rego
#       key: patch
#       value: "patch"
#     - type: rego
#       key: message
#       value: "\"Adding OPA sidecar & volume\""
#     - type: rego
#       key: allowed
#       value: "true"
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[patch]"

istio_opa_patches[patch] {
	opa_utils.injectable_object
	patch := [
		opa_utils.opa_patch,
		opa_utils.opa_volume_patch,
	]
}

# METADATA: library-snippet
# version: v1
# title: "Inject Missing Labels"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "mutating"
# description: >-
#   Ensures that the named set of labels exist; any missing label will be
#   added with its corresponding default value.
# schema:
#   type: object
#   properties:
#     labels:
#       type: object
#       title: Label key-value pairs
#       patternNames:
#         title: "Key (Example: env)"
#       additionalProperties:
#         type: string
#         title: "Value (Example: prod)"
#   additionalProperties: false
#   required:
#     - labels

add_missing_labels[decision] {
	# List of label key/values to add to the input object (if not already set)
	label_value := parameters.labels[label_name]
	escaped_name := replace(label_name, "/", "~1")

	# NOTE: currently will return a decision, each with single patch object, for each key/value.
	#       consider returning a single decision with multiple patch objects, one per key/value.

	not input.request.object.metadata.labels[label_name]
	decision := {
		"allowed": true,
		"message": sprintf("Set label '%s' to '%s'", [label_name, label_value]),
		"patch": [{
			"op": "add",
			"path": sprintf("/metadata/labels/%s", [escaped_name]),
			"value": label_value,
		}],
	}
}

# METADATA: library-snippet
# version: v1
# title: "Always Pull Images if Latest"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "mutating"
# description: >-
#   If container image uses `:latest` tag, ensure its `imagePullPolicy` is set to `Always`.

set_image_pull_policy_always_if_latest[decision] {
	utils.resources_with_containers[input.request.kind.kind]
	input_all_containers_with_path[[container, path]]

	workload.is_image_tag_latest(workload.parse_image(container.image))
	not container.imagePullPolicy

	decision := {
		"allowed": true,
		"message": sprintf("Set resource %v on container %v's image pull policy to Always", [utils.input_id, container.name]),
		"patch": [{
			"op": "add",
			"path": sprintf("%s/imagePullPolicy", [path]),
			"value": "Always",
		}],
	}
}

set_image_pull_policy_always_if_latest[decision] {
	utils.resources_with_containers[input.request.kind.kind]
	input_all_containers_with_path[[container, path]]

	workload.is_image_tag_latest(workload.parse_image(container.image))
	container.imagePullPolicy != "Always"

	decision := {
		"allowed": true,
		"message": sprintf("Set resource %v on container %v's image pull policy to Always", [utils.input_id, container.name]),
		"patch": [{
			"op": "replace",
			"path": sprintf("%s/imagePullPolicy", [path]),
			"value": "Always",
		}],
	}
}

# METADATA: library-snippet
# version: v1
# title: "Resources: Add Namespace Labels to Resource"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "mutating"
# description: >-
#   Ensures that the designated namespace labels are copied to all resources.
# schema:
#   type: object
#   properties:
#     labels_to_add:
#       type: array
#       title: "Add these labels from the namespace if the resource doesn’t already include them."
#       items:
#         type: string
#       uniqueItems: true
#     labels_to_override:
#       type: array
#       title: "Replace these labels with the corresponding namespace labels."
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false

inherit_namespace_labels[decision] {
	label_name := parameters.labels_to_add[_]
	ns := input.request.namespace
	ns_label_value := resources.namespaces[ns].metadata.labels[label_name]
	escaped_name := replace(label_name, "/", "~1")

	not input.request.object.metadata.labels[label_name]
	decision := {
		"allowed": true,
		"message": sprintf("Set label '%s' to '%s' (inherited from namespace '%s')", [label_name, ns_label_value, ns]),
		"patch": [{
			"op": "add",
			"path": sprintf("/metadata/labels/%s", [escaped_name]),
			"value": ns_label_value,
		}],
	}
}

inherit_namespace_labels[decision] {
	label_name := parameters.labels_to_override[_]
	ns := input.request.namespace
	ns_label_value := resources.namespaces[ns].metadata.labels[label_name]
	escaped_name := replace(label_name, "/", "~1")

	existing_value := input.request.object.metadata.labels[label_name]
	existing_value != ns_label_value
	decision := {
		"allowed": true,
		"message": sprintf("Set label '%s' to '%s' (inherited from namespace '%s', overriding existing value '%s')", [label_name, ns_label_value, ns, existing_value]),
		"patch": [{
			"op": "replace",
			"path": sprintf("/metadata/labels/%s", [escaped_name]),
			"value": ns_label_value,
		}],
	}
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Add Default Memory Limit"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "mutating"
# description: >-
#   Ensures that the container memory limit is set to a default value unless otherwise specified.
# schema:
#   type: object
#   properties:
#     memory_limit:
#       type: string
#       title: "Memory (example: 64Mi)"
#   additionalProperties: false
#   required:
#     - memory_limit

add_default_memory_limit[decision] {
	limit_value := parameters.memory_limit
	utils.resources_with_containers[input.request.kind.kind]
	input_all_containers_with_path[[container, path]]
	input_all_containers_with_path[[container, path]]

	# validate input memory
	utils.pow2_string_to_number(limit_value)

	not container.resources.limits.memory
	decision := {
		"allowed": true,
		"message": sprintf("Set resource %v on container %v's memory limit to %s", [utils.input_id, container.name, limit_value]),
		"patch": [{
			"op": "add",
			"path": sprintf("%s/resources/limits/memory", [path]),
			"value": limit_value,
		}],
	}
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Add Default CPU Limit"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "mutating"
# description: >-
#   Ensures that the container memory limit is set to a default value unless otherwise specified.
# schema:
#   type: object
#   properties:
#     cpu_limit:
#       type: string
#       title: "CPU (example: 250m)"
#   additionalProperties: false
#   required:
#     - cpu_limit
add_default_cpu_limit[decision] {
	limit_value := parameters.cpu_limit
	utils.resources_with_containers[input.request.kind.kind]
	input_all_containers_with_path[[container, path]]
	input_all_containers_with_path[[container, path]]

	# validate input cpu
	utils.cpu_to_number(limit_value)

	not container.resources.limits.cpu
	decision := {
		"allowed": true,
		"message": sprintf("Set resource %v on container %v's cpu limit to %s", [utils.input_id, container.name, limit_value]),
		"patch": [{
			"op": "add",
			"path": sprintf("%s/resources/limits/cpu", [path]),
			"value": limit_value,
		}],
	}
}

# ------------------------------------------------------------------------------
# Mutating helpers

input_all_containers_with_path[[container, path]] {
	container := input.request.object.spec.containers[i]
	path := sprintf("/spec/containers/%d", [i])
}

input_all_containers_with_path[[container, path]] {
	container := input.request.object.spec.initContainers[i]
	path := sprintf("/spec/initContainers/%d", [i])
}

input_all_containers_with_path[[container, path]] {
	container := input.request.object.spec.template.spec.containers[i]
	path := sprintf("/spec/template/spec/containers/%d", [i])
}

input_all_containers_with_path[[container, path]] {
	container := input.request.object.spec.template.spec.initContainers[i]
	path := sprintf("/spec/template/spec/initContainers/%d", [i])
}
