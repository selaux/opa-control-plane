package library.v1.kubernetes.admission.storage.v1

import data.kubernetes.resources
import data.library.parameters
import data.library.v1.kubernetes.utils.v1 as utils

# METADATA: library-snippet
# disabled: true # Not yet supported by data-driven UI.
# version: v1
# title: "Storage: Restrict Persistent Volume Storage Classes"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "storage"
# description: >-
#   Require every persistent volume claim to use an approved storage
#   class and (optionally) an approved access mode (`ReadOnlyMany`,
#   `ReadWriteMany`, `ReadWriteOnce`).
# details: >-
#   Every persistent volume claim can specify a storage class and an access mode
#   (`ReadOnlyMany`, `ReadWriteMany`, `ReadWriteOnce`). If no class is specified
#   by the claim, the default storage class will be used.
# resources:
#   inclusions:
#     - PersistentVolumeClaim
# schema:
#   type: object
#   properties:
#     classes:
#       type: object
#       title: Storage class
#       patternNames:
#         title: "Class (Example: fast)"
#       additionalProperties:
#         type: string
#         title: Access mode
#         enum:
#           - ReadOnlyMany
#           - ReadWriteMany
#           - ReadWriteOnce
#   additionalProperties: false
#   required:
#     - classes

deny_storage_class_access_mode_not_in_whitelist[reason] {
	input.request.kind.kind == "PersistentVolumeClaim"
	storage_class := input.request.object.spec.storageClassName
	storage_mode := input.request.object.spec.accessModes
	safe_class(storage_class, storage_mode)
	reason := sprintf("Resource %v uses an invalid storage class or mode %v/%v.", [utils.input_id, storage_class, storage_mode])
}

# class has no mode-list
safe_class(in_class, in_modes) {
	modes := parameters.classes[in_class]
	count(modes) == 0
}

# class has mode-list
safe_class(in_class, in_modes) {
	modes := parameters.classes[in_class]
	in_modes_set := cast_set(in_modes)
	count(in_modes_set - modes) == 0
}

# METADATA: library-snippet
# version: v1
# title: "Storage: Require Persistent Volume Encryption"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "storage"
# description: >-
#   Require persistent volume claims to request storage only from an encrypting
#   storage class.
# resources:
#   inclusions:
#     - PersistentVolumeClaim

enforce_encrypt[reason] {
	input.request.kind.kind == "PersistentVolumeClaim"
	storage_class_name := input.request.object.spec.storageClassName

	# Resolve the storage class and check for encryption
	storage_class := resources.storageclasses[storage_class_name]
	storage_class.parameters.encrypted != "true"
	reason := sprintf("Resource %v uses an unencrypted storage class v%.", [utils.input_id, storage_class_name])
}

# METADATA: library-snippet
# version: v1
# title: "Storage: Restrict Network File System (NFS) Mount Points"
# severity: "medium"
# platform: "kubernetes"
# resource-type: "storage"
# description: >-
#   Require every NFS mount to use an approved mount path.
# details: >-
#   Any NFS volume mounted into a pod may only use a mount point specified by a whitelist.
# resources:
#   inclusions:
#     - Pod
#     - DaemonSet
#     - Deployment
#     - ReplicaSet
#     - StatefulSet
# schema:
#   type: object
#   properties:
#     approved_mount_points:
#       type: object
#       title: Namespace
#       patternNames:
#         title: "Namespace (example: default)"
#       additionalProperties:
#         type: array
#         title: "Mount point (example: server:/path/on/volume)"
#         items:
#           type: string
#         uniqueItems: true
#   additionalProperties: false
#   required:
#     - approved_mount_points

enforce_nfs_mount_point_whitelist[reason] {
	utils.resources_with_containers[input.request.kind.kind]

	namespace := input.request.namespace

	allowed_mount_points := mount_points_by_ns[namespace]

	utils.input_all_volumes[volume]

	all_config_checks := {bad_server_or_path(nfs_config, volume.nfs) | allowed_mount_points[point]; nfs_config := get_nfs_server_path(point)}

	count(all_config_checks) > 0
	all(all_config_checks)

	reason := sprintf("Resource %v uses an NFS mount point %v that is not allowed.", [utils.input_id, volume.nfs.path])
}

enforce_nfs_mount_point_whitelist[reason] {
	utils.resources_with_containers[input.request.kind.kind]

	namespace := input.request.namespace
	not mount_points_by_ns[namespace]

	utils.input_all_volumes[volume]
	volume.nfs

	reason := sprintf("Resource %v uses an NFS mount point %v:%v, and no mount points are whitelisted for namespace %v.", [utils.input_id, volume.nfs.server, volume.nfs.path, namespace])
}

mount_points_by_ns[namespace] = mount_points {
	parameters.approved_mount_points[namespace] = mount_points
}

mount_points_by_ns[namespace] = mountpoints {
	label := data.kubernetes.resources.namespaces[namespace].metadata.labels["styra.com/mountpoints"]
	mountpoints := split(label, ",")
}

get_nfs_server_path(mount) = {"server": s, "path": p} {
	parts := split(mount, ":")
	count(parts) == 2
	s := parts[0]
	p := parts[1]
}

get_nfs_server_path(mount) = {"server": s, "path": p} {
	# the parameters are misconfigured, return the entire string for both parts
	parts := split(mount, ":")
	count(parts) != 2
	s := mount
	p := mount
}

bad_server_or_path(nfs_config, nfs_volume) {
	nfs_config.server != nfs_volume.server
}

bad_server_or_path(nfs_config, nfs_volume) {
	nfs_config.path != nfs_volume.path
}

bad_server_or_path(nfs_config, nfs_volume) = x {
	nfs_config.path == nfs_volume.path
	nfs_config.server == nfs_volume.server
	x := false
}
