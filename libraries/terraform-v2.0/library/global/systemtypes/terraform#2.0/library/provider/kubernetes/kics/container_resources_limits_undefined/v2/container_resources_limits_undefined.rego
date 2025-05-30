package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.container_resources_limits_undefined.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

types := {"init_container", "container"}

container_resources_limits_undefined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containerTypes := containers[y]
	not common_lib.valid_key(containerTypes, "resources")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].resources is undefined", [resourceType, name, specInfo.path, types[x], containerTypes]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].resources should be set", [resourceType, name, specInfo.path, types[x], containerTypes]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

container_resources_limits_undefined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers, "resources")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.resources is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.resources should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

container_resources_limits_undefined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	resources := {"limits", "requests"}
	containerResources := containers[y].resources
	resourceTypes := resources[_0]
	not common_lib.valid_key(containerResources, resourceTypes)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].resources.%s is undefined", [resourceType, name, specInfo.path, types[x], containerResources, resourceTypes]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].resources.%s should be set", [resourceType, name, specInfo.path, types[x], containerResources, resourceTypes]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

container_resources_limits_undefined_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	resources := {"limits", "requests"}
	resourceTypes := resources[_0]
	not common_lib.valid_key(containers.resources, resourceTypes)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.resources.%s is undefined", [resourceType, name, specInfo.path, types[x], resourceTypes]), "keyExpectedValue": sprintf("%s[%s].%s.%s.resources.%s should be set", [resourceType, name, specInfo.path, types[x], resourceTypes]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.resources", [resourceType, name, specInfo.path, types[x]])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Container Resources Limits Undefined"
# description: >-
#   Kubernetes container should have resource limitations defined such as CPU and memory
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.container_resources_limits_undefined"
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
container_resources_limits_undefined_snippet[violation] {
	container_resources_limits_undefined_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
