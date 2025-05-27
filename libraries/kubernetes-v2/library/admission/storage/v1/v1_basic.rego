package library.v1.kubernetes.admission.storage.v1

import data.kubernetes.resources
import data.library.parameters
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict FlexVolumes"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "storage"
# description: >-
#   Ensure resources use FlexVolume drivers from an approved list.
# schema:
#   type: object
#   properties:
#     whitelist:
#       type: array
#       title: "FlexVolume Drivers(Example: example/lvm, example/cifs)"
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

enforce_pod_flex_volume_drivers_whitelist[reason] {
	count(parameters.whitelist) > 0
	object := utils.get_object(input.request)
	volume := object.spec.volumes[_]
	flexVolumeDriver := volume.flexVolume.driver
	not strInPatterns(flexVolumeDriver, parameters.whitelist)
	reason := sprintf("Resource %v uses an unapproved FlexVolume driver %v.", [utils.input_id, volume])
}

strInPatterns(str, patterns) {
	find_match(str, patterns[_])
}

find_match(str, pattern) {
	str == pattern
}

find_match(_, "*")

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict Types of Volumes"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "storage"
# description: >-
#   Ensure resources use volume types from an approved list.
# schema:
#   type: object
#   properties:
#     whitelist:
#       type: array
#       title: "Pod Volume Types(Example: configMap, secret, emptyDir)"
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

enforce_pod_volume_type_whitelist[reason] {
	count(parameters.whitelist) > 0
	object := utils.get_object(input.request)
	volume := object.spec.volumes[_]
	not inobj(volume, parameters.whitelist)
	reason := sprintf("Resource %v uses an unapproved Volume Type %v.", [utils.input_id, volume])
}

inobj(object, fields) {
	has_field(object, fields[_])
}

has_field(object, field) {
	object[field]
}

has_field(_, "*")

# METADATA: library-snippet
# version: v1
# title: "Pod: Restrict FsGroup"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "storage"
# description: >-
#   Ensure resources use FsGroup from an approved whitelist.
# schema:
#   type: object
#   properties:
#     fs_group_rule:
#       type: string
#       enum:
#         - MustRunAs
#         - MayRunAs
#     fs_group_ranges:
#       type: array
#       title: Min-max fsGroup ID ranges (eg. 1-100)
#       items:
#         type: string
#       uniqueItems: true
#   additionalProperties: false
#   required:
#     - fs_group_rule
#     - fs_group_ranges
#   hint:order:
#     - fs_group_rule
#     - fs_group_ranges

enforce_pod_fsgroup_rule_whitelist[reason] {
	count(parameters.fs_group_ranges) > 0
	object := utils.get_object(input.request)
	not is_fsGroup_allowed(object.spec)
	reason := sprintf("Resource %v uses an unapproved fsGroup and this is not allowed.", [utils.input_id])
}

is_fsGroup_allowed(spec) {
	parameters.fs_group_rule == "MustRunAs"
	fsg := spec.securityContext.fsGroup
	range := parameters.fs_group_ranges[_]
	value_within_range(range, fsg)
}

is_fsGroup_allowed(spec) {
	parameters.fs_group_rule == "MayRunAs"
	fsg := spec.securityContext.fsGroup
	range := parameters.fs_group_ranges[_]
	value_within_range(range, fsg)
}

is_fsGroup_allowed(spec) {
	parameters.fs_group_rule == "MayRunAs"
	not spec.securityContext.fsGroup
}

value_within_range(range, value) {
	minmax := split(range, "-")
	min := to_number(minmax[0])
	max := to_number(minmax[1])
	min <= value
	max >= value
}
