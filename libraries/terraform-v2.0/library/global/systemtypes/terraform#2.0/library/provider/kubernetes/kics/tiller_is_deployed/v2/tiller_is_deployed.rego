package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.tiller_is_deployed.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

tiller_is_deployed_inner[result] {
	resource := input.document[i].resource[resourceType]
	checkMetadata(resource[name].metadata)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].metadata refers to a Tiller resource", [resourceType, name]), "keyExpectedValue": sprintf("%s[%s].metadata should not refer any to a Tiller resource", [resourceType, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].metadata", [resourceType, name])}
}

types := {"init_container", "container"}

tiller_is_deployed_inner[result] {
	resource := input.document[i].resource[resourceType]
	spec := resource[name].spec
	containers := spec[types[x]]
	is_array(containers) == true
	some y
	contains(object.get(containers[y], "image", "undefined"), "tiller")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].spec.%s[%d].image contains a Tiller container", [resourceType, name, types[x], y]), "keyExpectedValue": sprintf("%s[%s].spec.%s[%d].image shouldn't have any Tiller containers", [resourceType, name, types[x], y]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].spec.%s", [resourceType, name, types[x]])}
}

tiller_is_deployed_inner[result] {
	resource := input.document[i].resource[resourceType]
	spec := resource[name].spec
	containers := spec[types[x]]
	is_object(containers) == true
	contains(object.get(containers, "image", "undefined"), "tiller")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].spec.%s.image contains a Tiller container", [resourceType, name, types[x]]), "keyExpectedValue": sprintf("%s[%s].spec.%s.image shouldn't have any Tiller containers", [resourceType, name, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].spec.%s.image", [resourceType, name, types[x]])}
}

tiller_is_deployed_inner[result] {
	resource := input.document[i].resource[resourceType]
	spec := resource[name].spec
	checkMetadata(spec.template.metadata)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].spec.template.metadata does not refer to any Tiller resource", [resourceType, name]), "keyExpectedValue": sprintf("%s[%s].spec.template.metadata should not refer to any Tiller resource", [resourceType, name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].spec.template.metadata", [resourceType, name])}
}

tiller_is_deployed_inner[result] {
	resource := input.document[i].resource[resourceType]
	spec := resource[name].spec.template.spec
	containers := spec[types[x]]
	is_object(containers) == true
	contains(object.get(containers, "image", "undefined"), "tiller")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].spec.template.spec.%s.image contains a Tiller container", [resourceType, name, types[x]]), "keyExpectedValue": sprintf("%s[%s].spec.template.spec.%s.image shouldn't have any Tiller containers", [resourceType, name, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].spec.template.spec.%s.image", [resourceType, name, types[x]])}
}

tiller_is_deployed_inner[result] {
	resource := input.document[i].resource[resourceType]
	spec := resource[name].spec.template.spec
	containers := spec[types[x]]
	is_array(containers) == true
	contains(object.get(containers[y], "image", "undefined"), "tiller")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].spec.template.spec.%s[%d].image contains a Tiller container", [resourceType, name, types[x], y]), "keyExpectedValue": sprintf("%s[%s].spec.template.spec.%s[%d].image shouldn't have any Tiller containers", [resourceType, name, types[x], y]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].spec.template.%s", [resourceType, name, types[x]])}
}

checkMetadata(metadata) {
	contains(metadata.name, "tiller")
}

checkMetadata(metadata) {
	object.get(metadata.labels, "app", "undefined") == "helm"
}

checkMetadata(metadata) {
	contains(object.get(metadata.labels, "name", "undefined"), "tiller")
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Tiller (Helm v2) Is Deployed"
# description: >-
#   Check if Tiller is deployed.
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.tiller_is_deployed"
#   impact: ""
#   remediation: ""
#   severity: "high"
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
tiller_is_deployed_snippet[violation] {
	tiller_is_deployed_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
