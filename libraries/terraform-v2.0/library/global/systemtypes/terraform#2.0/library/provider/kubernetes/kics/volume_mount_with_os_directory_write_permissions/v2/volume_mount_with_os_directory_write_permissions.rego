package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.volume_mount_with_os_directory_write_permissions.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

types := {"init_container", "container"}

volume_mount_with_os_directory_write_permissions_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	is_object(containers[y].volume_mount) == true
	is_os_dir(containers[y].volume_mount)
	containers[y].volume_mount.read_only == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s[%d].volume_mount.read_only is set to false", [resourceType, name, specInfo.path, types[x], y]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].volume_mount.read_only should be set to true", [resourceType, name, specInfo.path, types[x], y]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.volume_mount.read_only", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line(array.concat(["resource", resourceType, name], split(specInfo.path, ".")), [types[x], y, "volume_mount", "read_only"])}
}

volume_mount_with_os_directory_write_permissions_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	volumeMounts := containers[y].volume_mount
	is_array(volumeMounts) == true
	is_os_dir(volumeMounts[j])
	volumeMounts[j].read_only == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s[%d].volume_mount[%d].read_only is set to false", [resourceType, name, specInfo.path, types[x], y, j]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].volume_mount[%d].read_only should be set to true", [resourceType, name, specInfo.path, types[x], y, j]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.volume_mount.read_only", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line(array.concat(["resource", resourceType, name], split(specInfo.path, ".")), [types[x], y, "volume_mount", j, "read_only"])}
}

volume_mount_with_os_directory_write_permissions_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	volumeMounts := containers.volume_mount
	is_object(volumeMounts) == true
	is_os_dir(volumeMounts)
	volumeMounts.read_only == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.volume_mount.read_only is set to false", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.volume_mount.read_only should be set to true", [resourceType, name, specInfo.path, types[x]]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.volume_mount.read_only", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line(array.concat(["resource", resourceType, name], split(specInfo.path, ".")), [types[x], "volume_mount", "read_only"])}
}

volume_mount_with_os_directory_write_permissions_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	volumeMounts := containers.volume_mount
	is_array(volumeMounts) == true
	is_os_dir(volumeMounts[j])
	volumeMounts[j].read_only == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.volume_mount[%d].read_only is set to false", [resourceType, name, specInfo.path, types[x], j]), "keyExpectedValue": sprintf("%s[%s].%s.%s.volume_mount[%d].read_only should be set to true", [resourceType, name, specInfo.path, types[x], j]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.volume_mount.read_only", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line(array.concat(["resource", resourceType, name], split(specInfo.path, ".")), [types[x], "volume_mount", j, "read_only"])}
}

volume_mount_with_os_directory_write_permissions_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	volumeMounts := containers[y].volume_mount
	is_object(volumeMounts) == true
	is_os_dir(volumeMounts)
	not common_lib.valid_key(volumeMounts, "read_only")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].volume_mount.read_only is undefined", [resourceType, name, specInfo.path, types[x], y]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].volume_mount.read_only should be set", [resourceType, name, specInfo.path, types[x], y]), "remediation": "read_only = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.volume_mount", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line(array.concat(["resource", resourceType, name], split(specInfo.path, ".")), [types[x], y, "volume_mount"])}
}

volume_mount_with_os_directory_write_permissions_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	volumeMounts := containers[y].volume_mount
	is_array(volumeMounts) == true
	is_os_dir(volumeMounts[j])
	volumeMountTypes := volumeMounts[_]
	not common_lib.valid_key(volumeMountTypes, "read_only")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].volume_mount[%d].read_only is undefined", [resourceType, name, specInfo.path, types[x], y, volumeMountTypes]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].volume_mount[%d].read_only should be set", [resourceType, name, specInfo.path, types[x], y, volumeMountTypes]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.volume_mount", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line(array.concat(["resource", resourceType, name], split(specInfo.path, ".")), [types[x], y, "volume_mount", j])}
}

volume_mount_with_os_directory_write_permissions_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	volumeMounts := containers.volume_mount
	is_object(volumeMounts) == true
	is_os_dir(volumeMounts)
	not common_lib.valid_key(volumeMounts, "read_only")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.volume_mount.read_only is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.volume_mount.read_only should be set", [resourceType, name, specInfo.path, types[x]]), "remediation": "read_only = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.volume_mount", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line(array.concat(["resource", resourceType, name], split(specInfo.path, ".")), [types[x], "volume_mount"])}
}

volume_mount_with_os_directory_write_permissions_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	volumeMounts := containers.volume_mount
	is_array(volumeMounts) == true
	is_os_dir(volumeMounts[j])
	volumeMountTypes := volumeMounts[j]
	not common_lib.valid_key(volumeMountTypes, "read_only")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.volume_mount[%d].read_only is undefined", [resourceType, name, specInfo.path, types[x], j]), "keyExpectedValue": sprintf("%s[%s].%s.%s.volume_mount[%d].read_only should be set", [resourceType, name, specInfo.path, types[x], j]), "remediation": "read_only = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.volume_mount", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line(array.concat(["resource", resourceType, name], split(specInfo.path, ".")), [types[x], "volume_mount", j])}
}

is_os_dir(volumeMounts) {
	hostSensitiveDir = {"/bin", "/sbin", "/boot", "/cdrom", "/dev", "/etc", "/home", "/lib", "/media", "/proc", "/root", "/run", "/seLinux", "/srv", "/usr", "/var"}
	startswith(volumeMounts.mount_path, hostSensitiveDir[_])
} else {
	volumeMounts.mount_path == "/"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Volume Mount With OS Directory Write Permissions"
# description: >-
#   Containers can mount sensitive folders from the hosts, giving them potentially dangerous access to critical host configurations and binaries.
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.volume_mount_with_os_directory_write_permissions"
#   impact: ""
#   remediation: ""
#   severity: "medium"
#   resource_category: ""
#   control_category: ""
#   rule_link: "https://docs.styra.com/systems/terraform/snippets"
#   platform:
#     name: "terraform"
#     versions:
#       min: "v0.12"
#       max: "v1.3"
#   provider:
#     name: "kubernetes"
#     versions:
#       min: "v2"
#       max: "v2"
#   rule_targets:
# schema:
#   decision:
#     - type: rego
#       key: allowed
#       value: "false"
#     - type: rego
#       key: message
#       value: "violation.message"
#     - type: rego
#       key: metadata
#       value: "violation.metadata"
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[violation]"
volume_mount_with_os_directory_write_permissions_snippet[violation] {
	volume_mount_with_os_directory_write_permissions_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
