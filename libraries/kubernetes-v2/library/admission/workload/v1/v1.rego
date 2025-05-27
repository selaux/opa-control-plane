package library.v1.kubernetes.admission.workload.v1

import data.kubernetes.resources
import data.library.parameters
import data.library.v1.kubernetes.admission.util.v1 as util
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Pods: Prohibit Mounting of `ConfigMap` Resources"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prevent pods from referencing `ConfigMap` resources that contain the restricted
#   keys you specify.
# schema:
#   type: object
#   properties:
#     prohibited_keys:
#       type: array
#       title: "Keys (Example: password)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_keys

deny_configmap_items_in_blacklist[reason] {
	count(parameters.prohibited_keys) > 0
	volume := input.request.object.spec.volumes[_]
	item := volume.configMap.items[_]
	parameters.prohibited_keys[item.key]
	reason := sprintf("Resource %v uses prohibited keys from `ConfigMap` in pod volumes.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Namespace: Prohibit Namespace Changes"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prevent changes from being made to a list of specified namespaces.
# schema:
#   type: object
#   properties:
#     prohibited_namespaces:
#       type: array
#       title: "Name (Example: kube-system)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_namespaces

deny_namespace_in_blacklist[reason] {
	count(parameters.prohibited_namespaces) > 0
	not util.is_service_account
	black_item := parameters.prohibited_namespaces[_]
	black_item == input.request.object.metadata.namespace
	reason := sprintf("Changes cannot be made to the namespace %v.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Pods: Prohibit Specified Host Paths"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prevent volumes from accessing prohibited paths on the host node’s file system.
# schema:
#   type: object
#   properties:
#     prohibited_host_paths:
#       type: array
#       title: "Host paths (Example: /proc*)"
#       description: >-
#         Use glob patterns to specify the host paths that cannot be accessed.
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_host_paths

deny_host_path_in_blacklist[reason] {
	count(parameters.prohibited_host_paths) > 0
	volume := input.request.object.spec.volumes[_]
	item := parameters.prohibited_host_paths[_]
	glob.match(item, [], volume.hostPath.path)
	reason := sprintf("Resource %v uses a prohibited host path.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Restrict Images (Globs)"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Restrict container images to images pulled from specified registries (Host) and
#   repository paths specified as a path with optional wildcard globs.
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet
#     - Job
#     - DaemonSet
# schema:
#   type: object
#   properties:
#     whitelist:
#       type: object
#       title: Registry
#       patternNames:
#         title: "Host (Example: quay.io)"
#       additionalProperties:
#         type: array
#         title: "Image path (Example: argoproj/*)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - whitelist

repository_unsafe_glob[reason] {
	input_all_container[container]
	image_name := container.image
	parsed_image := parse_image(image_name)
	not match_host_registry_glob(parsed_image, parameters.whitelist)
	reason := sprintf("Resource %v includes container image '%v' and this registry is not whitelisted.", [utils.input_id, image_name])
}

# registry has image-list
match_host_registry_glob(parsed_image, whitelist) {
	safe_images := whitelist[safe_host]
	parsed_image.host == safe_host
	safe_images[pattern]
	glob.match(pattern, ["/"], parsed_image.repo)
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit Images (Blocklist - Exact)"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prohibit container images from specified registries (Host) and
#   (optionally) from specified repository image paths.
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet
#     - Job
#     - DaemonSet
#     - Service
#     - Endpoint
#     - Ingress
# schema:
#   type: object
#   properties:
#     blocklist:
#       type: object
#       title: Registry
#       patternNames:
#         title: "Host (Example: gcr.io)"
#       additionalProperties:
#         type: array
#         title: "Image path (Example: argoproj/rollouts)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - blocklist

block_repository_exact[reason] {
	input_all_container[container]
	image_name := container.image
	parsed_image := parse_image(image_name)
	match_host_registry(parsed_image, parameters.blocklist)
	reason := sprintf("Resource %v includes container image '%v' from a prohibited registry.", [utils.input_id, image_name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit Images (Blocklist - Globs)"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prohibit container images from specified registries (Host) and
#   repository paths specified as a path with optional wildcard globs.
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet
#     - Job
#     - DaemonSet
# schema:
#   type: object
#   properties:
#     blocklist:
#       type: object
#       title: Registry
#       patternNames:
#         title: "Host (Example: quay.io)"
#       additionalProperties:
#         type: array
#         title: "Image path (Example: argoproj/*)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - blocklist

block_repository_glob[reason] {
	input_all_container[container]
	image_name := container.image
	parsed_image := parse_image(image_name)
	match_host_registry_glob(parsed_image, parameters.blocklist)
	reason := sprintf("Resource %v includes container image '%v' from a prohibited registry", [utils.input_id, image_name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Verify CPU and Memory Requirements"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure all containers specify both CPU and memory requirements.
# details: >-
#   Ensures that containers specify at least one of `resources.requests` (minimum
#   guaranteed) or `resources.limits` (maximum allowed) for both `cpu` and
#   `memory`. A container is guaranteed to have as much memory as it requests,
#   but is not allowed to use more memory than its limit. For more information, see
#   [Specify a memory request and a memory limit](https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/#specify-a-memory-request-and-a-memory-limit)
#   page.

expect_container_resource_requirements[reason] {
	input_all_container[container]
	not container.resources.requests.cpu
	not container.resources.limits.cpu
	reason := sprintf("Resource %v on container %v is missing CPU requirements.", [utils.input_id, container.name])
}

expect_container_resource_requirements[reason] {
	input_all_container[container]
	not container.resources.requests.memory
	not container.resources.limits.memory
	reason := sprintf("Resource %v on container %v is missing memory requirements.", [utils.input_id, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Service: Prohibit `NodePort` Setting"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prevents exposing a `NodePort` (Node IP addresses) for a service.

expect_no_nodeport[reason] {
	input.request.kind.kind == "Service"
	input.request.object.spec.type == "NodePort"
	reason := sprintf("Resource %v should not create a `NodePort` type.", [utils.input_id])
}

# METADATA: library-snippet
# disabled: true # Broken and thus deprecated, new rules will be replacing this one.
# version: v1
# title: "Containers: Require Resource Limits"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure all containers specify both CPU and memory limits.
# schema:
#   type: object
#   properties:
#     CPULimit:
#       type: object
#       title: "Range for CPU limit"
#       properties:
#         low_cpu:
#           type: string
#           title: "Lower CPU limit"
#         high_cpu:
#           type: string
#           title: "Upper CPU limit"
#       hint:order:
#         - low_cpu
#         - high_cpu
#
#   additionalProperties: false

expect_container_resource_limits[reason] {
	input_all_container[container]
	not container.resources.limits.cpu
	reason := sprintf("Resource %v on container %v is missing CPU limits.", [utils.input_id, container.name])
}

expect_container_resource_limits[reason] {
	parameters.CPULimit.low_cpu != 0
	input_all_container[container]
	container.resources.limits.cpu
	request = to_number(container.resources.limits.cpu)
	expect_low = to_number(parameters.CPULimit.low_cpu)
	request < expect_low
	reason := sprintf("Resource %v on container %v has CPU limit under minimum allowed value.", [utils.input_id, container.name])
}

expect_container_resource_limits[reason] {
	parameters.CPULimit.high_cpu != 0
	input_all_container[container]
	container.resources.limits.cpu
	request = to_number(container.resources.limits.cpu)
	expect_high = to_number(parameters.CPULimit.high_cpu)
	request > expect_high
	reason := sprintf("Resource %v on container %v has CPU limit exceeding maximum value.", [utils.input_id, container.name])
}

expect_container_resource_limits[reason] {
	input_all_container[container]
	not container.resources.limits.memory
	reason := sprintf("Resource %v on container %v is missing memory limits.", [utils.input_id, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Require CPU Limits"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure all containers specify CPU limits.
# schema:
#   type: object
#   properties:
#     minimum_cpu_limit:
#       type: string
#       title: "CPU (Example: 100m, 0.2, 2)"
#     maximum_cpu_limit:
#       type: string
#       title: "CPU (Example: 100m, 0.2, 2)"
#   additionalProperties: false
#   required:
#     - minimum_cpu_limit
#     - maximum_cpu_limit
#   hint:order:
#     - minimum_cpu_limit
#     - maximum_cpu_limit

ensure_container_cpu_limits[reason] {
	input_all_container[container]
	not container.resources.limits.cpu
	reason := sprintf("Resource %v on container %v is missing CPU limits.", [utils.input_id, container.name])
}

ensure_container_cpu_limits[reason] {
	parameters.minimum_cpu_limit
	input_all_container[container]
	container.resources.limits.cpu
	request = utils.cpu_to_number(container.resources.limits.cpu)
	expect_low = utils.cpu_to_number(parameters.minimum_cpu_limit)
	request < expect_low
	reason := sprintf("Resource %v on container %v has CPU limit under minimum value.", [utils.input_id, container.name])
}

ensure_container_cpu_limits[reason] {
	parameters.maximum_cpu_limit
	input_all_container[container]
	container.resources.limits.cpu
	request = utils.cpu_to_number(container.resources.limits.cpu)
	expect_high = utils.cpu_to_number(parameters.maximum_cpu_limit)
	request > expect_high
	reason := sprintf("Resource %v on container %v has CPU limit exceeding maximum value.", [utils.input_id, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Require Memory Limits"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure all containers specify memory limits. Note: Memory limits are specified in units from bytes (example: 512) to exabytes (example: 1.2E or 1.2Ei).
# schema:
#   type: object
#   properties:
#     minimum_memory_limit:
#       type: string
#       title: "Memory (Example: 128M, 1.1G)"
#     maximum_memory_limit:
#       type: string
#       title: "Memory (Example: 128M, 1.1G)"
#   additionalProperties: false
#   required:
#     - minimum_memory_limit
#     - maximum_memory_limit
#   hint:order:
#     - minimum_memory_limit
#     - maximum_memory_limit

ensure_container_memory_limits[reason] {
	input_all_container[container]
	not container.resources.limits.memory
	reason := sprintf("Resource %v on container %v is missing memory limits.", [utils.input_id, container.name])
}

ensure_container_memory_limits[reason] {
	parameters.minimum_memory_limit
	input_all_container[container]
	container.resources.limits.memory
	request = utils.pow2_string_to_number(container.resources.limits.memory)
	expect_low = utils.pow2_string_to_number(parameters.minimum_memory_limit)
	request < expect_low
	reason := sprintf("Resource %v on container %v has memory limit under minimum value.", [utils.input_id, container.name])
}

ensure_container_memory_limits[reason] {
	parameters.maximum_memory_limit
	input_all_container[container]
	container.resources.limits.memory
	request = utils.pow2_string_to_number(container.resources.limits.memory)
	expect_high = utils.pow2_string_to_number(parameters.maximum_memory_limit)
	request > expect_high
	reason := sprintf("Resource %v on container %v has memory limit exceeding maximum value.", [utils.input_id, container.name])
}

# TODO: Update deny_pod_without_required_node_selectors rule implementation to work on a
# pod-by-pod basis.

# METADATA: library-snippet
# disabled: true # Not reviewed.
# version: v1
# title: "Pods: Require Node Selectors"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Ensure a pod specifies node selectors that match an approved list.
# schema:
#   type: object
#   properties:
#     pod:
#       type: string
#       title: "Pod name (Example: lamp-server)"
#     selectors:
#       type: object
#       title: Node label
#       patternNames:
#         title: "Key (Example: diskType)"
#       additionalProperties:
#         type: string
#         title: "Value (Example: ssd)"
#   additionalProperties: false
#   required:
#     - pod
#     - selectors

deny_pod_without_required_node_selectors[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	object := utils.get_object(input.request)
	pod_name := object.metadata.name
	object.spec.nodeSelector != parameters.selectors[pod_name]
	reason := sprintf("Resource %v does not satisfy node selector constraint.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Nodes: Prohibit Master Workloads"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Prevent workloads from being deployed to master nodes.
# resources:
#   inclusions:
#     - Pod
#     - DaemonSet
#     - Deployment
#     - ReplicaSet
#     - StatefulSet

block_master_toleration[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	tolerations := get_tolerations(input.request)
	toleration := tolerations[_]

	# An empty "key" with operator "Exists" matches all keys,
	# values and effects which means this pod will tolerate everything.
	toleration.operator == "Exists"
	not toleration.key
	reason := sprintf("Resource %v tolerates everything", [utils.input_id])
}

block_master_toleration[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	tolerations := get_tolerations(input.request)
	toleration := tolerations[_]
	toleration.key == "node-role.kubernetes.io/master"
	toleration.operator == "Equal"
	toleration.value == "true"
	toleration.effect == "NoSchedule"
	reason := sprintf("Resource %v tolerates master node taint.", [utils.input_id])
}

block_master_toleration[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	tolerations := get_tolerations(input.request)
	toleration := tolerations[_]

	# An empty effect matches all effects with given key
	toleration.key == "node-role.kubernetes.io/master"
	toleration.operator == "Exists"
	reason := sprintf("Resource %v tolerates master node taint.", [utils.input_id, input.request.object.metadata.name])
}

# METADATA: library-snippet
# version: v1
# title: "Nodes: Prohibit Toleration Keys (Exact)"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prevent workloads with blacklisted toleration keys from being deployed to specific dedicated nodes.
# schema:
#   type: object
#   properties:
#     prohibited_keys:
#       type: array
#       title: Keys (e.g., dedicated)
#       description: Prohibited toleration keys
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - prohibited_keys

deny_toleration_keys_in_blacklist[reason] {
	count(parameters.prohibited_keys) > 0
	utils.resources_with_containers[input.request.kind.kind]
	tolerations := get_tolerations(input.request)
	toleration := tolerations[_]
	parameters.prohibited_keys[toleration.key]
	reason := sprintf("Resource %v contains restricted toleration key %v.", [utils.input_id, toleration.key])
}

# METADATA: library-snippet
# version: v1
# title: "Nodes: Prohibit nodeName-based Workload Assignment"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Prevent workloads from specifying nodeName to exploit direct scheduling
# resources:
#   inclusions:
#     - Pod
#     - DaemonSet
#     - Deployment
#     - ReplicaSet
#     - StatefulSet

block_nodename_assignment[reason] {
	utils.resources_with_containers[input.request.kind.kind]

	# nodeName should not be present in the spec
	node_name := get_nodename(input.request)

	reason := sprintf("Resource %v specifies a nodeName: %v", [utils.input_id, node_name])
}

# METADATA: library-snippet
# version: v1
# title: "Deployment: Require Update Strategy"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Ensure that an approved update strategy is specified for every deployment.
# schema:
#   type: object
#   properties:
#     update_strategy:
#       type: string
#       title: Update strategy
#       enum:
#         - Recreate
#         - RollingUpdate
#     max_unavailable_min:
#       type: string
#       title: Specify the maximum number of Pods allowed to be unavailable during an update.
#     max_surge_min:
#       type: string
#       title: Number of pods (e.g., 5% or 2)
#       description: Specify the minimum number of Pods that can be created during an update (above the number of Pods required during normal operation).
#   additionalProperties: false

require_update_strategy[reason] {
	parameters.update_strategy != ""
	input.request.kind.kind = "Deployment"
	parameters.update_strategy != input.request.object.spec.strategy.type
	reason := sprintf("Resource %v has different update strategy type from expected %v.", [utils.input_id, parameters.update_strategy])
}

# We disable this because there will always be a value for rollingUpdate.maxSurge. System has default value of 25%
# require_update_strategy[reason] {
# 	input.request.kind.kind = "Deployment"
# 	parameters.max_surge_min != ""
# 	not input.request.object.spec.strategy.rollingUpdate.maxSurge
# 	reason := sprintf("Resource %v is missing rollingUpdate.maxSurge.", [utils.input_id])
# }

require_update_strategy[reason] {
	input.request.kind.kind = "Deployment"
	parameters.max_surge_min != ""
	larger_than_fixed_or_percent(parameters.max_surge_min, input.request.object.spec.strategy.rollingUpdate.maxSurge)
	reason := sprintf("Resource %v has maxSurge lower than expected %v.", [utils.input_id, parameters.max_surge_min])
}

# We disable this because there will always be a value for rollingUpdate.maxUnavailable. System has default value of 25%
# require_update_strategy[reason] {
# 	input.request.kind.kind = "Deployment"
# 	parameters.max_unavailable_min != ""
# 	not input.request.object.spec.strategy.rollingUpdate.maxUnavailable
# 	reason := sprintf("Resource %v is missing rollingUpdate.maxUnavailable.", [utils.input_id])
# }

require_update_strategy[reason] {
	input.request.kind.kind = "Deployment"
	parameters.max_unavailable_min != ""
	larger_than_fixed_or_percent(parameters.max_unavailable_min, input.request.object.spec.strategy.rollingUpdate.maxUnavailable)
	reason := sprintf("Resource %v has maxUnavailable lower than expected %v.", [utils.input_id, parameters.max_unavailable_min])
}

# We disable this because there will always be update strategy. System has default value.
# require_update_strategy[reason] {
# 	input.request.kind.kind = "Deployment"
# 	parameters.updateStrategy
# 	not input.request.object.spec.strategy.type
# 	reason := sprintf("Resource %v is missing update strategy type.", [utils.input_id])
# }

# This is dedicated for comparing RollingUpdate.maxUnavailable
# and RollingUpdate.maxSurge
larger_than_fixed_or_percent(val1, val2) {
	is_number(val1)
	is_number(val2)
	to_number(val1) > to_number(val2)
}

larger_than_fixed_or_percent(val1, val2) {
	is_string(val1)
	is_number(val2)
	percentage_to_number(val1) > to_number(val2)
}

larger_than_fixed_or_percent(val1, val2) {
	is_number(val1)
	is_string(val2)
	to_number(val1) > percentage_to_number(val2)
}

larger_than_fixed_or_percent(val1, val2) {
	is_string(val1)
	is_string(val2)
	retrieve_percentage(val1) > retrieve_percentage(val2)
}

target_size = input.request.object.spec.replicas

target_size = 1 {
	not input.request.object.spec.replicas
}

percentage_to_number(val) = number {
	number := (to_number(retrieve_percentage(val)) * target_size) / 100
}

retrieve_percentage(val) = percentage {
	percentage := to_number(substring(val, 0, count(val) - 1))
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Require Liveness Probe"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Ensure every container sets a liveness probe.
# schema:
#   type: object
#   properties:
#     min_period_seconds:
#       type: number
#       description: Minimum interval in seconds to perform probe
#   additionalProperties: false

require_liveness_probe[reason] {
	not is_creating_jobs
	input_regular_container[container]
	not container.livenessProbe
	reason := sprintf("Resource %v on container %v is missing liveness probe.", [utils.input_id, container.name])
}

require_liveness_probe[reason] {
	not is_creating_jobs
	parameters.min_period_seconds
	input_regular_container[container]
	container.livenessProbe
	not container.livenessProbe.periodSeconds
	reason := sprintf("Resource %v on container %v is missing periodSeconds in liveness probe.", [utils.input_id, container.name])
}

require_liveness_probe[reason] {
	not is_creating_jobs
	parameters.min_period_seconds
	input_regular_container[container]
	container.livenessProbe
	container.livenessProbe.periodSeconds < parameters.min_period_seconds
	reason := sprintf("Resource %v on container %v liveness probe interval is less than %v.", [utils.input_id, container.name, parameters.min_period_seconds])
}

is_creating_jobs {
	input.request.kind.kind == "Job"
}

is_creating_jobs {
	input.request.kind.kind == "CronJob"
}

# METADATA: library-snippet
# deprecated: true
# version: v1
# title: "Containers: Check For Liveness Probe"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Ensure every container sets a liveness probe.
# schema:
#   type: object
#   properties:
#     periodSecondsMin:
#       type: number
#       description: Minimum value of how often (in seconds) to perform the probe
#   additionalProperties: false

ensure_liveness_probe[reason] {
	input_regular_container[container]
	not container.livenessProbe
	reason := sprintf("Resource %v on container %v is missing liveness probe.", [utils.input_id, container.name])
}

ensure_liveness_probe[reason] {
	parameters.periodSecondsMin != 0
	input_regular_container[container]
	container.livenessProbe
	not container.livenessProbe.periodSeconds
	reason := sprintf("Resource %v on container %v is missing periodSeconds in liveness probe.", [utils.input_id, container.name])
}

ensure_liveness_probe[reason] {
	parameters.periodSecondsMin != 0
	input_regular_container[container]
	container.livenessProbe
	container.livenessProbe.periodSeconds < parameters.periodSecondsMin
	reason := sprintf("Resource %v on container %v liveness probe interval is less than %v.", [utils.input_id, container.name, parameters.periodSecondsMin])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Require Readiness Probe"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Ensure every container sets a readiness probe.
# schema:
#   type: object
#   properties:
#     min_period_seconds:
#       type: number
#       description: Minimum interval in seconds to perform probe
#   additionalProperties: false

require_readiness_probe[reason] {
	input_regular_container[container]
	not container.readinessProbe
	reason := sprintf("Resource %v on container %v is missing readiness probe.", [utils.input_id, container.name])
}

require_readiness_probe[reason] {
	parameters.min_period_seconds
	input_regular_container[container]
	container.readinessProbe
	not container.readinessProbe.periodSeconds
	reason := sprintf("Resource %v on container %v is missing periodSeconds in readiness probe", [utils.input_id, container.name])
}

require_readiness_probe[reason] {
	parameters.min_period_seconds
	input_regular_container[container]
	container.readinessProbe
	container.readinessProbe.periodSeconds < parameters.min_period_seconds
	reason := sprintf("Resource %v on container %v has periodSeconds less than %v.", [utils.input_id, container.name, parameters.min_period_seconds])
}

# METADATA: library-snippet
# version: v1
# deprecated: true
# title: "Containers: Check For readiness Probe"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Ensure every container sets a readiness probe.
# schema:
#   type: object
#   properties:
#     periodSecondsMin:
#       type: number
#       description: Minimum value of how often (in seconds) to perform the probe
#   additionalProperties: false

ensure_readiness_probe[reason] {
	input_regular_container[container]
	not container.readinessProbe
	reason := sprintf("Resource %v on container %v is missing readiness probe.", [utils.input_id, container.name])
}

ensure_readiness_probe[reason] {
	parameters.periodSecondsMin != 0
	input_regular_container[container]
	container.readinessProbe
	not container.readinessProbe.periodSeconds
	reason := sprintf("Resource %v on container %v is missing periodSeconds in readiness probe.", [utils.input_id, container.name])
}

ensure_readiness_probe[reason] {
	parameters.periodSecondsMin != 0
	input_regular_container[container]
	container.readinessProbe
	container.readinessProbe.periodSeconds < parameters.periodSecondsMin
	reason := sprintf("Resource %v on container %v has periodSeconds less than %v.", [utils.input_id, container.name, parameters.periodSecondsMin])
}

# METADATA: library-snippet
# version: v1
# title: "Pods: Restrict Priority"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Ensure pods use approved minimum and maximum priority values.
# schema:
#   type: object
#   properties:
#     min:
#       type: number
#       description: Minimum priority value allowed
#     max:
#       type: number
#       description: Maximum priority value allowed
#   additionalProperties: false
#   required:
#     - max
#     - min
#   hint:order:
#     - min
#     - max

deny_pod_with_priority_out_of_bounds[reason] {
	parameters.min != 0
	priority_class_name := input.request.object.spec.priorityClassName
	priority_class := resources.priorityclasses[priority_class_name]
	priority := priority_class.value
	parameters.min > priority
	reason := sprintf("Resource %v priority %v below minimum allowed (%v).", [utils.input_id, priority, parameters.min])
}

deny_pod_with_priority_out_of_bounds[reason] {
	parameters.max != 0
	priority_class_name := input.request.object.spec.priorityClassName
	priority_class := resources.priorityclasses[priority_class_name]
	priority := priority_class.value
	parameters.max < priority
	reason := sprintf("Resource %v priority '%v' above maximum allowed (%v).", [utils.input_id, priority, parameters.max])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit Running as `root`"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Prevent all containers from running as `root` (user ID 0).
# schema:
#   type: object
#   properties:
#     exclude:
#       type: object
#       title: Registry
#       patternNames:
#         title: "Host (Example: gcr.io)"
#       additionalProperties:
#         type: array
#         title: "Image path (Example: argoproj/rollouts)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false

ensure_no_run_as_root[reason] {
	check_excluded
	input_all_container[container]
	image_name := container.image
	parsed_image := parse_image(image_name)

	# Only report error if the repo is not in the excluded list
	not match_host_registry(parsed_image, parameters.exclude)
	container.securityContext.runAsUser == 0
	reason := sprintf("Resource %v contains a security context specifying run as root.", [utils.input_id])
}

ensure_no_run_as_root[reason] {
	not check_excluded
	input_all_container[container]
	container.securityContext.runAsUser == 0
	reason := sprintf("Resource %v contains a security context specifying run as root.", [utils.input_id])
}

ensure_no_run_as_root[reason] {
	check_excluded
	input.request.kind.kind == "Pod"
	input_all_container[container]
	image_name := container.image
	parsed_image := parse_image(image_name)
	not match_host_registry(parsed_image, parameters.exclude)
	input.request.object.spec.securityContext.runAsUser == 0
	reason := sprintf("Resource %v contains a security context specifying run as root.", [utils.input_id])
}

ensure_no_run_as_root[reason] {
	not check_excluded
	input.request.kind.kind == "Pod"
	input.request.object.spec.securityContext.runAsUser == 0
	reason := sprintf("Resource %v contains a security context specifying run as root.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Storage Classes: Prohibit `Retain` Reclaim Policy"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prevent storage classes from using `Retain` as a reclaim policy.

deny_retain_policy[reason] {
	utils.kind_matches({"StorageClass"})
	input.request.object.reclaimPolicy == "Retain"
	reason := sprintf("Resource %v includes storage class with prohibited reclaim policy: Retain.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Resources: Require Valid Replicas"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Expect Resources to specify a minimum valid replica count (default: 1).
#   The default minimum count can be changed by specifying it in the parameter.
# resources:
#   verifications:
#     - Deployment
# schema:
#   type: object
#   properties:
#     replica_count:
#       type: number
#       description: "Value (Example: 2)"
#   additionalProperties: false
deny_invalid_replicas[reason] {
	utils.kind_matches({"Deployment"})
	input.request.object.spec.replicas < minimum_valid_replica_count
	reason := sprintf("Resource %v specifies an invalid number of replicas: %v", [utils.input_id, input.request.object.spec.replicas])
}

default minimum_valid_replica_count = 0

minimum_valid_replica_count = x {
	parameters.replica_count > 0
	x := parameters.replica_count
}

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict Bare Pods"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prohibit pods without a controller.
# details: >-
#   Requires that the pod must belong to one of the controllers like Deployment,
#   ReplicaSet, Job, CronJob, DaemonSet, StatefulSet

prohibit_bare_pods[reason] {
	input.request.kind.kind == "Pod"
	object := utils.get_object(input.request)
	not object.metadata.ownerReferences
	reason := sprintf("Bare pods are not allowed %v", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Deny workloads which are using default service account"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure all containers must not use `default` service account.

deny_default_service_account[reason] {
	object := utils.get_object(input.request)
	object.spec.serviceAccountName == "default"
	reason := sprintf("Resource %v has service account set as 'default' in pod spec and this is not allowed.", [utils.input_name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Deny workloads which are mounting service account token"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure all containers must not mount 'service account token'.

deny_service_account_token_mount[reason] {
	object := utils.get_object(input.request)
	not object.spec.automountServiceAccountToken == false
	reason := sprintf("Resource %v has mount service account token in pod spec and this is not allowed.", [utils.input_name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit windowsOptions HostProcess"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Restrict containers which contains windowsOptions HostProcess.
# resources:
#   inclusions:
#     - Pod
#     - DaemonSet
#     - Deployment
#     - Job

deny_host_process[reason] {
	invalid_host_process
	reason := sprintf("Resource %v hostProcess is set to true in pod spec and this is not allowed.", [utils.input_id])
}

invalid_host_process {
	object := utils.get_object(input.request)
	object.spec.securityContext.windowsOptions.hostProcess
}

invalid_host_process {
	input_all_container[container]
	container.securityContext.windowsOptions.hostProcess
}

# METADATA: library-snippet
# version: v1
# title: "Containers: -EXPERIMENTAL- Validate Image Signature with Sigstore Cosign"
# severity: "high"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   DO NOT USE IN PRODUCTION.
#   Validate Image Signatures with Cosign.
#   See docs.styra.com/das/systems/kubernetes/cosign for more details.
# details: >-
#   Prevents deployment of containers that do not have a valid cosign signature.
#   See docs.styra.com/das/systems/kubernetes/cosign for more details.
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet
#     - Job
#     - DaemonSet
#     - Service
#     - Endpoint
# schema:
#   type: object
#   properties:
#     verification_config:
#       type: string
#       title: "Example: data.cosign_config"
image_signature_verification_sigstore_cosign_v0_0_1[reason] {
	not kubelet_initiated

	# expected container image format "index.registry.io/hooli/piper:1.0.0"
	image := input_all_container[_].image
	parsed_image := parse_image(image)

	# check if name matches allowlist for verification
	cosign_parameters := parameters.verification_config.allow_with_verification[registry][img]
	matches_registry(registry, img, parsed_image.repo)

	request := cosign_validate_http_request(cosign_parameters, image)
	response := get_slp_response(request)
	error := validate_cosign_response(response)

	reason := sprintf("cosign verification failed for image %v due to '%v'\nparameters used %v", [image, error, cosign_parameters])
}

image_signature_verification_sigstore_cosign_v0_0_1[reason] {
	not kubelet_initiated

	# expected container image format "index.registry.io/hooli/piper:1.0.0"
	image := input_all_container[_].image
	parsed_image := parse_image(image)
	needs_verification(parsed_image.repo) != true
	skips_verification(parsed_image.repo) != true
	reason := sprintf("no cosign verification method specified for: %v", [image])
}

needs_verification(image_name) {
	# check if name is in allowlist for verification
	# allow_with_verification[registry] is a set
	parameters.verification_config.allow_with_verification[registry][img]
	matches_registry(registry, img, image_name) # == matches_registry(registry, img, image_name)
}

skips_verification(image_name) {
	# check if name is in allowlist for skipping verification
	# allow_without_verification[registry] is a list
	img := parameters.verification_config.allow_without_verification[registry][_]
	matches_registry(registry, img, image_name) # == matches_registry(registry, img, image_name)
}

registry_delimiters := ["/", ".", "-", "_"]

matches_registry(registry, img, image_name) {
	# for bare images "piper:1.0"
	registry == ""
	not contains(image_name, ".")
	glob.match(img, registry_delimiters, image_name)
} else {
	# for images with registry "gcr.io/nginx:1.0"
	glob.match(concat("/", [registry, img]), registry_delimiters, image_name)
}

# kubelet_initiated checks if the request was initiated by a system node or a kubelet.
# It is helpful for scenarios where the rule enforcement needs to be skipped.
# eg. if an erroneously created pod needs to be deleted, without this
# exception, the violating rule will need to be disabled for the delete
# operation to go through.
kubelet_initiated {
	# https://kubernetes.io/docs/reference/access-authn-authz/node/#rbac-node-permissions
	input.request.userInfo.groups[_] == "system:nodes"
}

cosign_validate_http_request(params, image) = {
	"url": "http://localhost:8080/internal/validate/cosign",
	"method": "POST",
	"timeout": "10s", # k8s webhook is configured with 30s timeout
	"headers": {"Content-Type": "application/json"},
	"body": {"request": object.union(params, {"keys": [image]})},
}

# define an empty response if SLP is unavailable
get_slp_response(req) = response {
	response := http.send(req)
} else = {}

validate_cosign_response(response) = res {
	response.status_code != 200
	res = sprintf("HTTP %v", [response.status_code])
} else = res {
	count(response.body.response.items) > 0
	errs = {err | err = response.body.response.items[_].error}
	count(errs) > 0
	res = sprintf("(errors): %v", [errs])
} else = res {
	count(response.body.response.systemError) > 0
	res = sprintf("(systemError): %v", [response.body.response.systemError])
} else = "SLP unavailable" {
	response == {}
}
