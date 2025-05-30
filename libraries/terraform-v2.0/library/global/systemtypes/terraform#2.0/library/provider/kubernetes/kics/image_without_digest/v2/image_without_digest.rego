package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.image_without_digest.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

types := {"init_container", "container"}

image_without_digest_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	containerTypes := containers[_]
	not common_lib.valid_key(containerTypes, "image")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s[%d].image is undefined", [resourceType, name, specInfo.path, types[x], containerTypes]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].image should be set", [resourceType, name, specInfo.path, types[x], containerTypes]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

image_without_digest_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_array(containers) == true
	image := containers[y].image
	not contains(image, "@")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s[%d].image does not have '@'", [resourceType, name, specInfo.path, types[x], y]), "keyExpectedValue": sprintf("%s[%s].%s.%s[%d].image has '@'", [resourceType, name, specInfo.path, types[x], y]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

image_without_digest_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	not common_lib.valid_key(containers, "image")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("%s[%s].%s.%s.image is undefined", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.image should be set", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s", [resourceType, name, specInfo.path, types[x]])}
}

image_without_digest_inner[result] {
	resource := input.document[i].resource[resourceType]
	specInfo := tf_lib.getSpecInfo(resource[name])
	containers := specInfo.spec[types[x]]
	is_object(containers) == true
	image := containers.image
	not contains(image, "@")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("%s[%s].%s.%s.image does not have '@'", [resourceType, name, specInfo.path, types[x]]), "keyExpectedValue": sprintf("%s[%s].%s.%s.image has '@'", [resourceType, name, specInfo.path, types[x]]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": resourceType, "searchKey": sprintf("%s[%s].%s.%s.image", [resourceType, name, specInfo.path, types[x]])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Image Without Digest"
# description: >-
#   Images should be specified together with their digests to ensure integrity
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.image_without_digest"
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
image_without_digest_snippet[violation] {
	image_without_digest_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
