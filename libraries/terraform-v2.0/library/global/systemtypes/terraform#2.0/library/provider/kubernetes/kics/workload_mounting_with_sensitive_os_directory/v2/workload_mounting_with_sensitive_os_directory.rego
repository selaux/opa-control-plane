package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.workload_mounting_with_sensitive_os_directory.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

workload_mounting_with_sensitive_os_directory_inner[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	metadata := resource.metadata
	volumes := resource.spec.volume
	isOSDir(volumes[j].path)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("Workload name '%s' is mounting a host sensitive OS directory '%s' with host_path", [resource.metadata.name, volumes[j].path]), "keyExpectedValue": sprintf("Workload name '%s' should not mount a host sensitive OS directory '%s' with host_path", [metadata.name, volumes[j].path]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_pod", "searchKey": sprintf("kubernetes_pod[%s].spec.volume.host_path.path", [name])}
}

workload_mounting_with_sensitive_os_directory_inner[result] {
	resource := input.document[i].resource.kubernetes_persistent_volume[name]
	metadata := resource.metadata
	volumes := resource.spec.volume
	isOSDir(volumes[j].path)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("Workload name '%s' is mounting a host sensitive OS directory '%s' with host_path", [resource.metadata.name, volumes[j].path]), "keyExpectedValue": sprintf("Workload name '%s' should not mount a host sensitive OS directory '%s' with host_path", [metadata.name, volumes[j].path]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_persistent_volume", "searchKey": sprintf("kubernetes_persistent_volume[%s].spec.volume.host_path.path", [name])}
}

isOSDir(mountPath) = result {
	hostSensitiveDir = {
		"/bin", "/sbin", "/boot", "/cdrom",
		"/dev", "/etc", "/home", "/lib",
		"/media", "/proc", "/root", "/run",
		"/seLinux", "/srv", "/usr", "/var",
	}

	result = listcontains(hostSensitiveDir, mountPath)
} else = result {
	result = mountPath == "/"
}

listcontains(dirs, elem) {
	startswith(elem, dirs[_])
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Workload Mounting With Sensitive OS Directory"
# description: >-
#   Workload is mounting a volume with sensitive OS Directory
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.workload_mounting_with_sensitive_os_directory"
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
workload_mounting_with_sensitive_os_directory_snippet[violation] {
	workload_mounting_with_sensitive_os_directory_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
