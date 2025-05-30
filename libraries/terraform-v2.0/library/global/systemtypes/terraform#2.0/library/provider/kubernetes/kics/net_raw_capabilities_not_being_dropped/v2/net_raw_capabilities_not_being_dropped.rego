package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.net_raw_capabilities_not_being_dropped.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

types := {"init_container", "container"}

net_raw_capabilities_not_being_dropped_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containerCapabilities := containers[_0].security_context.capabilities
	not common_lib.valid_key(containerCapabilities, "drop")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("k%s[%s].%s.%s[%d].security_context.capabilities.drop is undefined", [resourceType, name, specInfo.path, types[x], containerCapabilities]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].security_context.capabilities.drop should be set", [resourceType, name, specInfo.path, types[x], containerCapabilities]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

net_raw_capabilities_not_being_dropped_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	options := {"ALL", "NET_RAW"}
	dropList := containers[y].security_context.capabilities.drop
	not drop(dropList, options)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s[%d].security_context.capabilities.add is not ALL or NET_RAW", [resourceType, name, specInfo.path, types[x], y]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].security_context.capabilities.drop is ALL or NET_RAW", [resourceType, name, specInfo.path, types[x], y]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

net_raw_capabilities_not_being_dropped_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containerSecurity := containers[_0].security_context
	not common_lib.valid_key(containerSecurity, "capabilities")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].security_context.capabilities is undefined", [resourceType, name, specInfo.path, types[x], containerSecurity]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].security_context.capabilities should be set", [resourceType, name, specInfo.path, types[x], containerSecurity]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

net_raw_capabilities_not_being_dropped_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containersType := containers[_0]
	not common_lib.valid_key(containersType, "security_context")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].security_context is undefined", [resourceType, name, specInfo.path, types[x], containersType]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].security_context should be set", [resourceType, name, specInfo.path, types[x], containersType]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

net_raw_capabilities_not_being_dropped_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers.security_context.capabilities, "drop")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.security_context.capabilities.drop is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.security_context.capabilities.drop should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.security_context.capabilities", [resourceType, name, specInfo.path, types[x]])}
}

net_raw_capabilities_not_being_dropped_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	options := {"ALL", "NET_RAW"}
	not drop(containers.security_context.capabilities.drop, options)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.security_context.capabilities.drop is not ALL or NET_RAW", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.security_context.capabilities.drop is ALL or NET_RAW", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.security_context.capabilities.drop", [resourceType, name, specInfo.path, types[x]])}
}

net_raw_capabilities_not_being_dropped_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers.security_context, "capabilities")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.security_context.capabilities is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.security_context.capabilities should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.security_context", [resourceType, name, specInfo.path, types[x]])}
}

net_raw_capabilities_not_being_dropped_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers, "security_context")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.security_context is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.security_context should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

drop(array, elem) {
	upper(array[_]) == elem[_]
}

# METADATA: library-snippet
# version: v1
# title: "KICS: NET_RAW Capabilities Not Being Dropped"
# description: >-
#   Containers should drop 'ALL' or at least 'NET_RAW' capabilities
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.net_raw_capabilities_not_being_dropped"
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
net_raw_capabilities_not_being_dropped_snippet[violation] {
	net_raw_capabilities_not_being_dropped_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
