package library.v1.kubernetes.admission.workload.v1

import data.kubernetes.resources
import data.library.parameters
import data.library.v1.kubernetes.admission.util.v1 as util
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit `:latest` Image Tag"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prohibit container images that use the `:latest` tag.
# details: >-
#   Prevents deployment of containers that use the `:latest` tag to ensure you
#   can determine the version of the image currently running and can roll back properly,
#   if needed.
# suggestions:
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

block_latest_image_tag[reason] {
	image_name := input_all_container[_].image
	is_image_tag_latest(parse_image(image_name))
	reason := sprintf("Resource %v should not use the 'latest' tag on container image %v.", [utils.input_id, image_name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Always Pull Images"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Ensure every container sets its `imagePullPolicy` to `Always`.

check_image_pull_policy[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	input_all_container[container]
	not container.imagePullPolicy
	not is_image_tag_latest(parse_image(container.image))
	reason := sprintf("Resource %v on container %v does not have an image pull policy.", [utils.input_id, container.name])
}

check_image_pull_policy[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	input_all_container[container]
	container.imagePullPolicy != "Always"

	# We need to make sure no latest tags are presented.
	reason := sprintf("Resource %v on container %v has image pull policy other than Always %v.", [utils.input_id, container.name, container.imagePullPolicy])
}

is_image_tag_latest(parsed_image) {
	parsed_image.tag == "latest"
}

is_image_tag_latest(parsed_image) {
	parsed_image.digest == null
	parsed_image.tag == null
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Restrict Images (Exact)"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Restrict container images to images pulled from specified registries (Host) and (optionally)
#   from specified repository image paths.
# suggestions:
#   schema: all_registries
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
#     whitelist:
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
#     - whitelist

repository_unsafe_exact[reason] {
	input_all_container[container]
	image_name := container.image
	parsed_image := parse_image(image_name)
	not match_host_registry(parsed_image, parameters.whitelist)
	reason := sprintf("Resource %v includes container image '%v' from a prohibited registry.", [utils.input_id, image_name])
}

# whitelist is a map from the name of the registry to all of the images within it
# map to [] implying no restriction on images
all_registries["whitelist"] = {x: [] | monitor_all_registries[x]}

monitor_all_registries[x] {
	data.library.v1.kubernetes.monitor.v2.namespaced_objects[[resource, params]]
	wrapped := data.library.v1.kubernetes.utils.v1.admission_with_namespace(resource, params)
	input_all_registries[x] with input as wrapped
}

monitor_all_registries[x] {
	data.library.v1.kubernetes.monitor.v2.global_objects[[resource, params]]
	wrapped := data.library.v1.kubernetes.utils.v1.admission_with_namespace(resource, params)
	input_all_registries[x] with input as wrapped
}

input_all_registries[parsed_image.host] {
	input_all_container[container]
	parsed_image := parse_image(container.image)
}

# registry has no image-list
match_host_registry(parsed_image, whitelist) {
	safe_images := whitelist[safe_host]
	parsed_image.host == safe_host
	count(safe_images) == 0
}

# registry has image-list
match_host_registry(parsed_image, whitelist) {
	safe_images := whitelist[safe_host]
	parsed_image.host == safe_host
	safe_images[parsed_image.repo]
}

# "spec": https://github.com/moby/moby/blob/master/image/spec/v1.1.md
# SO: https://stackoverflow.com/questions/37861791/how-are-docker-image-names-parsed
# [host[:port]]/.../.../...:tag@digest
parse_image(image) = result {
	extradigest := parse_digest(split(image, "@"))
	repotag := parse_repo_tag(split(extradigest.extra, ":"))
	hostportrepo := parse_host_port_repo(split(repotag.repo, "/"))
	result := {
		"host": hostportrepo.host,
		"port": hostportrepo.port,
		"repo": hostportrepo.repo,
		"tag": repotag.tag,
		"digest": extradigest.digest,
	}
}

parse_digest(atparts) = digest {
	count(atparts) == 1
	digest = {
		"extra": atparts[0],
		"digest": null,
	}
}

parse_digest(atparts) = digest {
	count(atparts) == 2
	digest = {
		"extra": atparts[0],
		"digest": atparts[1],
	}
}

parse_repo_tag(colonparts) = repotag {
	# foo/bar
	count(colonparts) == 1
	repotag := {
		"repo": colonparts[0],
		"tag": null,
	}
}

parse_repo_tag(colonparts) = repotag {
	# foo/bar:0.2
	count(colonparts) == 2
	not contains(colonparts[1], "/")
	repotag := {
		"repo": colonparts[0],
		"tag": colonparts[1],
	}
}

parse_repo_tag(colonparts) = repotag {
	# acme.com:8181/foo
	count(colonparts) == 2
	contains(colonparts[1], "/")
	repotag := {
		"repo": concat(":", colonparts),
		"tag": null,
	}
}

parse_repo_tag(colonparts) = repotag {
	# acme.com:8181/foo/bar:0.2
	count(colonparts) == 3
	repotag := {
		"repo": concat(":", [colonparts[0], colonparts[1]]),
		"tag": colonparts[2],
	}
}

# localhost
parse_host_port_repo(slashparts) = h {
	slashparts[0] == "localhost"
	repo := concat("/", tail(slashparts))
	h := {"host": slashparts[0], "port": null, "repo": repo}
}

# explicit port
parse_host_port_repo(slashparts) = h {
	hostport := split(slashparts[0], ":")
	repo := concat("/", tail(slashparts))

	# Make sure hostport[1] contains only digits since to_number will panic on conversion failures
	port := to_number(assert_number(hostport[1]))
	h := {"host": hostport[0], "port": port, "repo": repo}
}

assert_number(x) = x {
	regex.match("^[0-9]*$", x)
}

# no port but '.' signifying host
parse_host_port_repo(slashparts) = h {
	not contains(slashparts[0], ":")
	contains(slashparts[0], ".")
	repo := concat("/", tail(slashparts))
	h := {"host": slashparts[0], "port": null, "repo": repo}
}

# no port, no '.', not localhost
parse_host_port_repo(slashparts) = h {
	not slashparts[0] == "localhost"
	not contains(slashparts[0], ":")
	not contains(slashparts[0], ".")
	repo := concat("/", slashparts)
	h := {"host": "", "port": null, "repo": repo}
}

# return an array without index 0
tail(arr) = t {
	t := [v | v := arr[i]; i > 0]
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit Privileged Mode"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Prevent containers from running in privileged mode.
# suggestions:

block_privileged_mode[reason] {
	input_all_container[container]
	container.securityContext.privileged
	reason := sprintf("Resource %v should not run container %v in privileged mode.", [utils.input_id, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Pods: Prohibit Host Network Access"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Prevent pods from accessing the host network, including the host loopback device.

deny_host_network[reason] {
	utils.kind_matches({"Pod"})
	input.request.object.spec.hostNetwork == true
	reason := sprintf("Pod %v cannot be created with hostNetwork enabled.", [utils.input_id])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Restrict Host Paths"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure every container’s `volumeMounts.mountPath` property includes only an
#   approved host path.
# suggestions:
#   schema: all_host_paths
# schema:
#   type: object
#   properties:
#     allowed:
#       type: array
#       title: "Paths (Example: /var/lib/mysql)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - allowed

deny_host_path_not_in_whitelist[reason] {
	count(parameters.allowed) > 0
	utils.resources_with_containers[input.request.kind.kind]
	input_all_container[container]
	volume_mount := container.volumeMounts[_]
	volume_name := volume_mount.name
	volume := utils.input_all_volumes[_]
	volume.name == volume_name
	not inlist(parameters.allowed, volume.hostPath.path)
	reason := sprintf("Resource %v on container %v has disallowed host path %v.", [utils.input_id, container.name, volume.hostPath.path])
}

all_host_paths["allowed"] = monitor_all_host_paths

monitor_all_host_paths[x] {
	data.library.v1.kubernetes.monitor.v2.namespaced_objects[[resource, params]]
	wrapped := data.library.v1.kubernetes.utils.v1.admission_with_namespace(resource, params)
	input_host_paths_aux[x] with input as wrapped
}

input_host_paths_aux[volume.hostPath.path] {
	utils.resources_with_containers[input.request.kind.kind]

	# input_all_container[container]              # why are we doing this join in the rule above?
	# volume_mount := container.volumeMounts[_]
	# volume_name := volume_mount.name
	volume := utils.input_all_volumes[_]
	# volume.name == volume_name
}

inlist(list, elem) {
	glob.match(list[_], ["/"], elem)
}

# METADATA: library-snippet
# version: v1
# title: "Pods: Prohibit All Host Paths"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure pods don't have access on the host node’s file system.

deny_all_host_paths[reason] {
	utils.input_all_volumes[volumes]
	volumes.hostPath
	reason := sprintf("Resource %v should not have hostPath %v.", [utils.input_id, volumes.hostPath.path])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Require Read-Only File Systems"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Ensure every container’s root file system is read-only.
# details: >-
#   This policy covers both cases in which (1) `readOnlyRootFilesystem` is not defined
#   and (2) `readOnlyRootFilesystem` is false.

missing_read_only_filesystem[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	input_all_container[container]

	not container.securityContext.readOnlyRootFilesystem
	reason := sprintf("Resource %v on container %v does not have a read-only root file system set to true.", [utils.input_id, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Disallow privilege escalation"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Expect `allowPrivilegeEscalation` to be set to false

deny_privilege_escalation[reason] {
	input_all_container[container]
	not container.securityContext.allowPrivilegeEscalation == false
	reason := sprintf("Resource %v should not have allowPrivilegeEscalation set to true for container %v.", [utils.input_id, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Restrict Approved ProcMount Type"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure containers use an approved `procMount` type.
# schema:
#   type: object
#   properties:
#     whitelist:
#       type: array
#       title: "Container Proc Mount Type (Example: Default or Unmasked)"
#       items:
#         type: string
#       uniqueItems: true
#   required:
#     - whitelist
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet

enforce_proc_mount_type_whitelist[reason] {
	count(parameters.whitelist) > 0
	object := utils.get_object(input.request)
	input.request.operation == "CREATE"

	container := input_all_container[_]
	not procmount_approved(container.securityContext.procMount)
	reason := sprintf("Resource %v uses unapporved procMount type %v.", [utils.input_id, container.securityContext.procMount])
}

procmount_approved(procmount) {
	procmount == parameters.whitelist[_]
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit Insecure Capabilities"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure that unauthorized capabilities _aren’t_ set in any container’s
#   `securityContext.capabilities.add` section and _are_ set in the
#   corresponding `drop` section.
# schema:
#   type: object
#   properties:
#     capabilities:
#       type: array
#       title: "Prohibited capabilities (Example: SETUID)"
#       items:
#         type: string
#       uniqueItems: true
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
#   required:
#     - capabilities

deny_capabilities_in_blacklist[reason] {
	check_excluded
	count(parameters.capabilities) > 0
	utils.resources_with_containers[input.request.kind.kind]
	input_all_container[container]
	image_name := container.image
	parsed_image := parse_image(image_name)

	# Only report errors if the image is not excluded.
	not match_host_registry(parsed_image, parameters.exclude)
	added := {cap | cap = container.securityContext.capabilities.add[_]}
	remaining := parameters.capabilities & added
	n := count(remaining)
	n > 0
	reason := sprintf("Resource %v on container %v has added prohibited capabilities %v.", [utils.input_id, container.name, remaining])
}

deny_capabilities_in_blacklist[reason] {
	not check_excluded
	count(parameters.capabilities) > 0
	utils.resources_with_containers[input.request.kind.kind]
	input_all_container[container]
	added := {cap | cap = container.securityContext.capabilities.add[_]}
	remaining := parameters.capabilities & added
	n := count(remaining)
	n > 0
	reason := sprintf("Resource %v on container %v has added prohibited capabilities %v.", [utils.input_id, container.name, remaining])
}

deny_capabilities_in_blacklist[reason] {
	not check_excluded
	count(parameters.capabilities) > 0
	utils.resources_with_containers[input.request.kind.kind]
	input_all_container[container]
	dropped := {cap | cap = container.securityContext.capabilities.drop[_]}
	remaining_from_blacklist := parameters.capabilities - dropped
	remaining := remaining_from_blacklist & default_add_capabilities
	n := count(remaining)
	n > 0
	reason := sprintf("Resource %v on container %v has not dropped recommended capabilities %v.", [utils.input_id, container.name, remaining])
}

deny_capabilities_in_blacklist[reason] {
	check_excluded
	count(parameters.capabilities) > 0
	utils.resources_with_containers[input.request.kind.kind]
	input_all_container[container]
	image_name := container.image
	parsed_image := parse_image(image_name)
	not match_host_registry(parsed_image, parameters.exclude)
	dropped := {cap | cap = container.securityContext.capabilities.drop[_]}
	remaining_from_blacklist := parameters.capabilities - dropped
	remaining := remaining_from_blacklist & default_add_capabilities
	n := count(remaining)
	n > 0
	reason := sprintf("Resource %v on container %v has not dropped recommended capabilities %v.", [utils.input_id, container.name, remaining])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit Insecure Baseline Profile Capabilities"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Restrict unauthorized capabilities set in the `securityContext.capabilities.add` section.
# resources:
#   inclusions:
#     - Pod
#     - DaemonSet
#     - Deployment
#     - Job

deny_baseline_capabilities[reason] {
	deny_capabilities_baseline[reason]
}

deny_capabilities_baseline[reason] {
	object := utils.get_object(input.request)
	capabilities := {cap | cap = object.spec.securityContext.capabilities.add[_]}
	remaining := capabilities - default_baseline_add_capabilities
	count(remaining) > 0
	reason := sprintf("Resource %v has added prohibited capabilities %v in pod spec and this is not allowed.", [utils.input_id, remaining])
}

deny_capabilities_baseline[reason] {
	input_all_container[container]
	capabilities := {cap | cap = container.securityContext.capabilities.add[_]}
	remaining := capabilities - default_baseline_add_capabilities
	count(remaining) > 0
	reason := sprintf("Resource %v on container %v has added prohibited capabilities %v and this is not allowed.", [utils.input_id, container.name, remaining])
}

default_baseline_add_capabilities = {
	"SETPCAP", "MKNOD", "AUDIT_WRITE",
	"CHOWN", "DAC_OVERRIDE",
	"FOWNER", "FSETID", "KILL",
	"SETGID", "SETUID", "NET_BIND_SERVICE",
	"SYS_CHROOT", "SETFCAP",
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit Insecure Capabilities (Restricted Profile)"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure containers drop 'ALL' capabilities and
#   only add the 'NET_BIND_SERVICE' capability
#   in the `securityContext.capabilities.add` and
#   `securityContext.capabilities.drop` sections.
# resources:
#   inclusions:
#     - Pod
#     - DaemonSet
#     - Deployment
#     - Job

deny_restricted_capabilities[reason] {
	deny_capabilities_restricted[reason]
}

deny_capabilities_restricted[reason] {
	input_all_container[container]
	added_cap := {cap | cap = container.securityContext.capabilities.add[_]}
	remaining := added_cap - {"NET_BIND_SERVICE"}
	count(remaining) > 0
	reason := sprintf("Resource %v on container %v has added prohibited capabilities %v.", [utils.input_id, container.name, remaining])
}

deny_capabilities_restricted[reason] {
	input_all_container[container]
	dropped_cap := {cap | cap = container.securityContext.capabilities.drop[_]}
	dropped_cap[_] != "ALL"
	reason := sprintf("Resource %v on container %v has not dropped recommended capabilities %v.", [utils.input_id, container.name, dropped_cap])
}

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict sysctls used"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure every container uses only allowed sysctls.
# schema:
#   type: object
#   properties:
#     forbidden_sysctls:
#       type: array
#       title: "Exclude specific sysctls (e.g. net.core.somaxconn)"
#       items:
#         type: string
#       uniqueItems: true
#     allowed_unsafe_sysctls:
#       type: array
#       title: "Allowed unsafe sysctls (e.g. net.core.somaxconn)"
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - forbidden_sysctls
#     - allowed_unsafe_sysctls

deny_unsafe_and_forbidden_sysctls[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	object := utils.get_object(input.request)
	sysctl := object.spec.securityContext.sysctls[_]
	not safe_sysctls[sysctl.name]
	not parameters.allowed_unsafe_sysctls[sysctl.name]
	reason := sprintf("Resource %v uses unsafe sysctls %v", [utils.input_id, sysctl.name])
}

deny_unsafe_and_forbidden_sysctls[reason] {
	count(parameters.forbidden_sysctls) > 0
	utils.resources_with_containers[input.request.kind.kind]
	object := utils.get_object(input.request)
	sysctl := object.spec.securityContext.sysctls[_]
	parameters.forbidden_sysctls[sysctl.name]
	reason := sprintf("Resource %v uses forbidden sysctls %v", [utils.input_id, sysctl.name])
}

deny_unsafe_and_forbidden_sysctls[reason] {
	count(parameters.forbidden_sysctls) > 0
	utils.resources_with_containers[input.request.kind.kind]
	object := utils.get_object(input.request)
	parameters.forbidden_sysctls["*"]
	count(object.spec.securityContext.sysctls) > 0
	reason := sprintf("Resource %v uses forbidden sysctl %v", [utils.input_id, object.spec.securityContext.sysctls])
}

safe_sysctls = {"kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.tcp_syncookies"}

# METADATA: library-snippet
# version: v1
# title: "Containers: Must run as non-root"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure containers must not run as root (MustRunAsNonRoot).
# details: >-
#   Requires that the pod be run with `runAsNonRoot` assigned `true` or with `runAsUser` assigned a
#   non-zero value. When neither `runAsUser` nor `runAsNonRoot` are specified, the request will be denied.
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet

enforce_container_mustrunasnonroot[reason] {
	object := utils.get_object(input.request)
	container := input_all_container[_]
	not container_runs_as_non_root(container, object)
	reason := sprintf("Resource %v must run as non-root", [utils.input_id])
}

# if runAsUser is specified in both podSecurityContext and containerSecurityContext
# the value in containerSecurityContext takes precedence

container_runs_as(container, object) = userid {
	userid := container.securityContext.runAsUser
}

container_runs_as(container, object) = userid {
	not container.securityContext.runAsUser
	userid := object.spec.securityContext.runAsUser
}

container_has_no_run_as_user(container, object) {
	not container.securityContext.runAsUser
	not object.spec.securityContext.runAsUser
}

# how does k8s resolve conflicts between runAsUser and runAsNonRoot?
# if runAsNonRoot is set, k8s evaluates the container at runtime and fails if the it is running with root user
# If set in both SecurityContext and PodSecurityContext, the value specified in
# SecurityContext takes precedence.

# Container explicitly runs with userid==0
container_runs_as_non_root(container, object) {
	container_runs_as(container, object) != 0
}

# Container sets runAsNonRoot
container_runs_as_non_root(container, object) {
	container_runs_as(container, object) != 0
	container.securityContext.runAsNonRoot == true
}

container_runs_as_non_root(container, object) {
	container_has_no_run_as_user(container, object)
	container.securityContext.runAsNonRoot == true
}

container_runs_as_non_root(container, object) {
	container_has_no_run_as_user(container, object)
	object.spec.securityContext.runAsNonRoot == true
}

# Container doesn't set any runAsNonRoot, but object does.
container_runs_as_non_root(container, object) {
	container_runs_as(container, object) != 0
	not container.security.Context.runAsNonRoot
	object.spec.securityContext.runAsNonRoot == true
}

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict Seccomp Profiles"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure resources use Seccomp profiles from an approved list.
# schema:
#   type: object
#   properties:
#     whitelist:
#       type: array
#       title: "Pod Seccomp Profiles (Example: runtime/default, docker/default)"
#       items:
#         type: string
#       uniqueItems: true
#   required:
#     - whitelist
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet

enforce_seccomp_profile_whitelist[reason] {
	count(parameters.whitelist) > 0
	object := utils.get_object(input.request)
	annotations := object.metadata.annotations
	container_name := input_all_container[_].name
	not container_has_valid_seccomp_profile(container_name, annotations)
	reason := sprintf("Resource %v uses an unapproved Seccomp Profile. Allowed Seccomp Profiles: %v.", [utils.input_id, parameters.whitelist])
}

container_has_valid_seccomp_profile(container_name, annotations) {
	annotations[key]
	startswith(key, "container.seccomp.security.alpha.kubernetes.io/")
	contains(key, container_name)
	annotations[key] == parameters.whitelist[_]
}

container_has_valid_seccomp_profile(container_name, annotations) {
	annotations[key]
	startswith(key, "seccomp.security.alpha.kubernetes.io/pod")
	annotations[key] == parameters.whitelist[_]
}

container_has_valid_seccomp_profile(container_name, annotations) {
	"*" == parameters.whitelist[_]
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Restrict Unapproved Seccomp Profiles"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure that no resources are set to unapproved Seccomp Profiles
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet

deny_seccomp_profiles[reason] {
	deny_restricted_seccomp_profiles[reason]
}

allowed_seccomp_profiles = {"Localhost", "RuntimeDefault"}

deny_restricted_seccomp_profiles[reason] {
	object := utils.get_object(input.request)
	seccomp_profile := object.spec.securityContext.seccompProfile.type
	not allowed_seccomp_profiles[seccomp_profile]
	reason := sprintf("Resource %v uses an unapproved Seccomp Profile %v in pod spec and this is not allowed.", [utils.input_id, seccomp_profile])
}

deny_restricted_seccomp_profiles[reason] {
	input_all_container[container]
	seccomp_profile := container.securityContext.seccompProfile.type
	not allowed_seccomp_profiles[seccomp_profile]
	reason := sprintf("Resource %v uses an unapproved Seccomp Profile %v on container %v and this is not allowed.", [utils.input_id, seccomp_profile, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict Approved AppArmor Profiles"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure resources use AppArmor profiles from an approved list.
# schema:
#   type: object
#   properties:
#     whitelist:
#       type: array
#       title: "Pod AppArmor Profiles (Example: runtime/default, /bin/example)"
#       items:
#         type: string
#       uniqueItems: true
#   required:
#     - whitelist
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet

enforce_app_armor_profile_whitelist[reason] {
	count(parameters.whitelist) > 0
	object := utils.get_object(input.request)
	annotations := object.metadata.annotations
	container_name := input_all_container[_].name
	not container_has_valid_apparmor_profile(container_name, annotations)
	reason := sprintf("Resource %v uses an unapproved ArmorApp Profile. Allowed AppArmor Profiles: %v.", [utils.input_id, parameters.whitelist])
}

container_has_valid_apparmor_profile(container_name, annotations) {
	parameters.whitelist[_] == "*"
}

container_has_valid_apparmor_profile(container_name, annotations) {
	annotations[key]
	startswith(key, "container.apparmor.security.beta.kubernetes.io/")
	contains(key, container_name)
	annotations[key] == parameters.whitelist[_]
}

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict User IDs"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure containers run with an approved user ID (MustRunAs).
# schema:
#   type: object
#   properties:
#     user_id_ranges:
#       type: array
#       title: Min-max user ID ranges (eg. 1-100)
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - user_id_ranges
#   hint:order:
#     - user_id_ranges

enforce_pod_runas_userid_rule_whitelist[reason] {
	count(parameters.user_id_ranges) > 0
	object := utils.get_object(input.request)
	container := input_all_container[_]
	userid := container_runs_as(container, object)
	not value_in_ranges(userid, parameters.user_id_ranges)
	reason := sprintf("Resource %v runs as prohibited user ID %v", [utils.input_id, userid])
}

enforce_pod_runas_userid_rule_whitelist[reason] {
	count(parameters.user_id_ranges) > 0
	object := utils.get_object(input.request)
	container := input_all_container[_]
	container_has_no_run_as_user(container, object)
	reason := sprintf("Resource %v doesn’t define required runAsUser property", [utils.input_id])
}

value_in_ranges(value, ranges) {
	range := ranges[_]
	minmax := split(range, "-")
	min := to_number(minmax[0])
	max := to_number(minmax[1])
	value >= min
	value <= max
}

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict Group IDs"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure containers run with an approved group ID or, if `run_as_group_rule` is `MayRunAs`, no group ID.
# schema:
#   type: object
#   properties:
#     run_as_group_rule:
#       type: string
#       enum:
#         - MustRunAs
#         - MayRunAs
#     group_id_ranges:
#       type: array
#       title: Min-max group ID ranges (eg. 1-100)
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - run_as_group_rule
#     - group_id_ranges
#   hint:order:
#     - run_as_group_rule
#     - group_id_ranges

enforce_pod_runas_groupid_rule_whitelist[reason] {
	parameters.run_as_group_rule == "MustRunAs"
	object := utils.get_object(input.request)
	container := input_all_container[_]
	groupid := container_runs_as_group(container, object)
	not value_in_ranges(groupid, parameters.group_id_ranges)
	reason := sprintf("Resource %v runs as prohibited group ID %v", [utils.input_id, groupid])
}

enforce_pod_runas_groupid_rule_whitelist[reason] {
	parameters.run_as_group_rule == "MustRunAs"
	object := utils.get_object(input.request)
	container := input_all_container[_]
	container_has_no_run_as_group(container, object)
	reason := sprintf("Resource %v doesn’t define required runAsGroup property", [utils.input_id])
}

enforce_pod_runas_groupid_rule_whitelist[reason] {
	parameters.run_as_group_rule == "MayRunAs"
	object := utils.get_object(input.request)
	container := input_all_container[_]
	groupid := container_runs_as_group(container, object)
	not value_in_ranges(groupid, parameters.group_id_ranges)
	reason := sprintf("Resource %v runs as prohibited group ID %v", [utils.input_id, groupid])
}

# if runAsGroup is specified in both podSecurityContext and containerSecurityContext
# the value in containerSecurityContext takes precedence

container_runs_as_group(container, object) = groupid {
	groupid := container.securityContext.runAsGroup
}

container_runs_as_group(container, object) = groupid {
	not container.securityContext.runAsGroup
	groupid := object.spec.securityContext.runAsGroup
}

container_has_no_run_as_group(container, object) {
	not container.securityContext.runAsGroup
	not object.spec.securityContext.runAsGroup
}

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict SeLinuxOptions"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure resources use only approved `SeLinuxOptions`.
# schema:
#   type: object
#   properties:
#     level:
#       type: string
#       title: "Level (eg. s1:c234,c567)"
#     role:
#       type: string
#       title: "Role (eg. sysadm_r)"
#     type:
#       type: string
#       title: "Type (eg. svirt_lxc_net_t)"
#     user:
#       type: string
#       title: "User (eg. sysadm_u)"
#   required:
#     - level
#     - role
#     - type
#     - user
# resources:
#   verifications:
#     - Pod
#     - Deployment
#     - ReplicaSet

# if seLinuxOptions present in (any) containers[_].spec and pod.spec, container[_].securityContext.seLinuxOptions
# takes precedence precedence over pod.spec.securityContext.seLinuxOptions.
enforce_selinux_options_whitelist[reason] {
	count(parameters) > 0
	object := utils.get_object(input.request)
	container := input_all_container[_]
	seloptions := get_seLinuxOptions(container, object.spec)
	not is_seloptions_allowed(seloptions)
	reason := sprintf("Resource %v runs with unapproved seLinuxOptions. Must be %v", [utils.input_id, parameters])
}

# container and pod both does not have securityContext.seLinuxOptions.
enforce_selinux_options_whitelist[reason] {
	count(parameters) > 0
	object := utils.get_object(input.request)
	container := input_all_container[_]
	not get_seLinuxOptions(container, object.spec)
	reason := sprintf("Resource %v runs with no seLinuxOptions. Must be %v.", [utils.input_id, parameters])
}

# case 1, pod spec does not have securityContext.seLinuxOptions
get_seLinuxOptions(container, spec) = selinuxoptions {
	selinuxoptions := container.securityContext.seLinuxOptions
}

# case 2, one of the containers spec does not have securityContext.seLinuxOptions, then inherit from pod-spec
get_seLinuxOptions(container, spec) = selinuxoptions {
	not container.securityContext.seLinuxOptions
	selinuxoptions := spec.securityContext.seLinuxOptions
}

is_seloptions_allowed(options) {
	count(parameters) == count(options)

	options_level := get_inputoption(options, "level")
	param_level := get_seloption(options_level, "level")
	param_level == options_level

	options_role := get_inputoption(options, "role")
	param_role := get_seloption(options_role, "role")
	param_role == options_role

	options_type := get_inputoption(options, "type")
	param_type := get_seloption(options_type, "type")
	param_type == options_type

	options_user := get_inputoption(options, "user")
	param_user := get_seloption(options_user, "user")
	param_user == options_user
}

get_seloption(input_value, key) = option_value {
	option_value := parameters[key]
}

else = option_value {
	option_value := input_value
}

get_inputoption(options, key) = option_value {
	option_value := options[key]
}

else = option_value {
	option_value := "unspecified"
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit Privileged Mode for Regular Containers"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Prevent Regular containers from running in privileged mode.

block_privileged_mode_regular_containers[reason] {
	input_regular_container[container]
	container.securityContext.privileged
	reason := sprintf("Resource %v should not run regular container %v in privileged mode.", [utils.input_id, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Prohibit Privileged Mode for Init Containers"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: Prevent init containers from running in privileged mode.

block_privileged_mode_init_containers[reason] {
	input_init_container[container]
	container.securityContext.privileged
	reason := sprintf("Resource %v should not run init container %v in privileged mode.", [utils.input_id, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Require Resource Requests"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure all containers specify both CPU and memory requests.
# details: >-
#   Ensures that containers specify the `resources.requests` (minimum guaranteed)
#   configuration setting for both `cpu` and `memory`.
# suggestions:

expect_container_resource_requests[reason] {
	input_all_container[container]
	not container.resources.requests.cpu
	reason := sprintf("Resource %v on container %v is missing CPU requests.", [utils.input_id, container.name])
}

expect_container_resource_requests[reason] {
	input_all_container[container]
	not container.resources.requests.memory
	reason := sprintf("Resource %v on container %v is missing memory requests.", [utils.input_id, container.name])
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Restrict Reclaim Policies"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure containers requesting persistent storage do so with an approved
#   reclaim policy.
# suggestions:
#   schema: universal_reclaim_policy
# details: >-
#   To handle containers with persistent volume claims but without an explicitly-set
#   storage class request, the `DefaultStorageClass` admission plugin has to run
#   before the `ValidatingAdmissionWebhook`.
# schema:
#   type: object
#   properties:
#     reclaim_policy:
#       type: string
#       title: Policy (Delete, Recycle, or Retain)
#       enum:
#         - Delete
#         - Recycle
#         - Retain
#   additionalProperties: false
#   required:
#     - reclaim_policy

deny_unexpected_reclaim_policy[reason] {
	input_all_container[container]

	# Resolve the volume mounts to volumes.
	volume_mount := container.volumeMounts[_]
	volume_name := volume_mount.name
	volume := input.request.object.spec.volumes[_] # shouldn't we be using 	volume := utils.input_all_volumes[_] here b/c of templates?
	volume.name == volume_name

	# Resolve the volumes to storage class.
	persistent_volume_claim := data.kubernetes.resources.persistentvolumeclaims[input.request.object.metadata.namespace][volume.persistentVolumeClaim.claimName]
	storage_class := data.kubernetes.resources.storageclasses[persistent_volume_claim.spec.storageClassName]

	storage_class.reclaimPolicy != parameters.reclaim_policy
	reason := sprintf("Resource %v includes a persistent volume claim with reclaim policy '%v'.", [utils.input_id, storage_class.reclaimPolicy])
}

# note: if either 0 or more than 1 reclaim policy then we return no value for "reclaim_policy"
universal_reclaim_policy["reclaim_policy"] = arr[0] {
	count(monitor_all_reclaims) == 1
	arr := [x | monitor_all_reclaims[x]]
}

# requires namespace since persistent-volume-claims are namespace objects
# Could make (much) faster by iterating over a known set of objects instead of all of them, e.g. Pods, Deployments, etc.
#   But wouldn't necessarily be a perfect fit unless deny rule applied to only those Kinds as well.
monitor_all_reclaims[x] {
	data.library.v1.kubernetes.monitor.v2.namespaced_objects[[resource, params]]
	wrapped := data.library.v1.kubernetes.utils.v1.admission_with_namespace(resource, params)
	input_all_reclaims[x] with input as wrapped
}

# list of all reclaim policies
input_all_reclaims[storage_class.reclaimPolicy] {
	input_all_container[container]

	# Resolve the volume mounts to volumes.
	volume_mount := container.volumeMounts[_]
	volume := utils.input_all_volumes[_]
	volume.name == volume_mount.name

	# Resolve the volumes to storage class.
	persistent_volume_claim := data.kubernetes.resources.persistentvolumeclaims[input.request.object.metadata.namespace][volume.persistentVolumeClaim.claimName]
	storage_class := data.kubernetes.resources.storageclasses[persistent_volume_claim.spec.storageClassName]
}

# METADATA: library-snippet
# version: v1
# title: "Containers: Require Non-default Namespace"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "workload"
# description: >-
#   Ensure that a container cannot be started in the Kubernetes `default` namespace.

deny_default_namespace[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	input.request.namespace == "default"
	reason := sprintf("Resource %v uses the default namespace.", [utils.input_id])
}

deny_default_namespace[reason] {
	utils.resources_with_containers[input.request.kind.kind]
	not input.request.namespace
	reason := sprintf("Resource %v uses the default namespace (namespace was not specified).", [utils.input_id])
}

# ------------------------------------------------------------------------------
# Helpers

check_excluded {
	parameters.exclude
	count(parameters.exclude) > 0
}

input_all_container[c] {
	c := input_regular_container[_]
}

input_all_container[c] {
	c := input_init_container[_]
}

input_regular_container[c] {
	c := input.request.object.spec.containers[_]
}

input_regular_container[c] {
	c := input.request.object.spec.ephemeralContainers[_]
}

input_regular_container[c] {
	c := input.request.object.spec.template.spec.containers[_]
}

input_regular_container[c] {
	c := input.request.object.spec.jobTemplate.spec.template.spec.containers[_]
}

input_init_container[c] {
	c := input.request.object.spec.initContainers[_]
}

input_init_container[c] {
	c := input.request.object.spec.template.spec.initContainers[_]
}

input_init_container[c] {
	c := input.request.object.spec.jobTemplate.spec.template.spec.initContainers[_]
}

get_tolerations(request) = result {
	request.kind.kind = "Pod"
	result := request.object.spec.tolerations
}

get_tolerations(request) = result {
	request.kind.kind = utils.resources_with_pods[_]
	result := request.object.spec.template.spec.tolerations
}

get_nodename(request) = result {
	request.kind.kind = "Pod"
	owner_kind := {owner | owner := input.request.object.metadata.ownerReferences[_]; owner.kind == "DaemonSet"}
	count(owner_kind) == 0
	result := input.request.object.spec.nodeName
}

get_nodename(request) = result {
	request.kind.kind = utils.resources_with_pods[_]
	not request.kind.kind = "DaemonSet"
	result := input.request.object.spec.template.spec.nodeName
}

default_add_capabilities = {
	"SETPCAP", "MKNOD", "AUDIT_WRITE",
	"CHOWN", "NET_RAW", "DAC_OVERRIDE",
	"FOWNER", "FSETID", "KILL",
	"SETGID", "SETUID", "NET_BIND_SERVICE",
	"SYS_CHROOT", "SETFCAP",
}
