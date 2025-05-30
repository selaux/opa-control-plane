package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.root_container_not_mounted_as_read_only.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

types := {"init_container", "container"}

root_container_not_mounted_as_read_only_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containersType := containers[_]
	not common_lib.valid_key(containersType, "security_context")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("k%s[%s].%s.%s[%d].security_context is undefined", [resourceType, name, specInfo.path, types[x], containersType]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].security_context should be set", [resourceType, name, specInfo.path, types[x], containersType]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.name={{%s}}", [resourceType, name, specInfo.path, types[x], containersType.name]), "searchLine": common_lib.build_search_line([resourceType, name, specInfo.path], [types[x]])}
}

root_container_not_mounted_as_read_only_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	common_lib.valid_key(containers[j], "security_context")
	not common_lib.valid_key(containers[j].security_context, "read_only_root_filesystem")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s[%d].security_context.read_only_root_filesystem is undefined", [resourceType, name, specInfo.path, types[x], j]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].security_context.read_only_root_filesystem should be set", [resourceType, name, specInfo.path, types[x], j]), "remediation": "read_only_root_filesystem = true", "remediationType": "addition", "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.name={{%s}}.security_context", [resourceType, name, specInfo.path, types[x], containers[j].name]), "searchLine": common_lib.build_search_line([resourceType, name, specInfo.path], [types[x], "security_context"])}
}

root_container_not_mounted_as_read_only_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	common_lib.valid_key(containers[y], "security_context")
	containers[y].security_context.read_only_root_filesystem == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s[%d].security_context.read_only_root_filesystem is not set to true", [resourceType, name, specInfo.path, types[x], y]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].security_context.read_only_root_filesystem should be set to true", [resourceType, name, specInfo.path, types[x], y]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.name={{%s}}.security_context.read_only_root_filesystem", [resourceType, name, specInfo.path, types[x], containers[y].name]), "searchLine": common_lib.build_search_line([resourceType, name, specInfo.path], [types[x], "security_context", "read_only_root_filesystem"])}
}

root_container_not_mounted_as_read_only_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers, "security_context")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.security_context is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.security_context should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line([resourceType, name, specInfo.path], [types[x]])}
}

root_container_not_mounted_as_read_only_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers.security_context, "read_only_root_filesystem")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.security_context.read_only_root_filesystem is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.security_context.read_only_root_filesystem should be set", [resourceType, name, specInfo.path, types[x]]), "remediation": "read_only_root_filesystem = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.security_context", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line([resourceType, name, specInfo.path], [types[x], "security_context"])}
}

root_container_not_mounted_as_read_only_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	containers.security_context.read_only_root_filesystem == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.security_context.read_only_root_filesystem is not set to true", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.security_context.read_only_root_filesystem should be set to true", [resourceType, name, specInfo.path, types[x]]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.security_context.read_only_root_filesystem", [resourceType, name, specInfo.path, types[x]]), "searchLine": common_lib.build_search_line([resourceType, name, specInfo.path], [types[x], "security_context", "read_only_root_filesystem"])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Root Container Not Mounted As Read-only"
# description: >-
#   Check if the root container filesystem is not being mounted as read-only.
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.root_container_not_mounted_as_read_only"
#   impact: ""
#   remediation: ""
#   severity: "low"
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
root_container_not_mounted_as_read_only_snippet[violation] {
	root_container_not_mounted_as_read_only_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
