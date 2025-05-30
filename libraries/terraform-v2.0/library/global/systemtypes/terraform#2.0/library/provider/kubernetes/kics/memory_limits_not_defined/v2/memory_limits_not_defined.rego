package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.memory_limits_not_defined.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

types := {"init_container", "container"}

memory_limits_not_defined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containerLimits := containers[y].resources.limits
	not common_lib.valid_key(containerLimits, "memory")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].resources.limits.memory is undefined", [resourceType, name, specInfo.path, types[x], containerLimits]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].resources.limits.memory should be set", [resourceType, name, specInfo.path, types[x], containerLimits]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

memory_limits_not_defined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers.resources.limits, "memory")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.resources.limits.memory is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.resources.limits.memory should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.resources.limits", [resourceType, name, specInfo.path, types[x]])}
}

memory_limits_not_defined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containersType := containers[_0]
	not common_lib.valid_key(containersType, "resources")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].resources is undefined", [resourceType, name, specInfo.path, types[x], containersType]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].resources should be set", [resourceType, name, specInfo.path, types[x], containersType]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

memory_limits_not_defined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers, "resources")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.resources is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.resources should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

memory_limits_not_defined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containersType := containers[_0]
	not common_lib.valid_key(containersType.resources, "limits")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].resources.limits is undefined", [resourceType, name, specInfo.path, types[x], containersType]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].resources.limits should be set", [resourceType, name, specInfo.path, types[x], containersType]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

memory_limits_not_defined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers.resources, "limits")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.resources.limits is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.resources.limits should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.resources", [resourceType, name, specInfo.path, types[x]])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Memory Limits Not Defined"
# description: >-
#   Memory limits should be defined for each container. This prevents potential resource exhaustion by ensuring that containers consume not more than the designated amount of memory
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.memory_limits_not_defined"
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
memory_limits_not_defined_snippet[violation] {
	memory_limits_not_defined_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
