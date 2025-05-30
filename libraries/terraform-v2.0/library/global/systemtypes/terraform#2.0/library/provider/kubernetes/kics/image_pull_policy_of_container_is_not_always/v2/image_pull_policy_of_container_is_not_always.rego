package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.image_pull_policy_of_container_is_not_always.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

image_pull_policy_of_container_is_not_always_inner[result] {
	types := {"kubernetes_deployment": "spec.template.spec.container", "kubernetes_pod": "spec.container"}
	resource_prefix := types[x]
	resource := input.document[i].resource[x][name]
	path := checkPath(resource)
	path.image_pull_policy != "Always"
	not contains(path.image, ":latest")
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'image_pull_policy' is incorrect", "keyExpectedValue": "Attribute 'image_pull_policy' should be defined as 'Always'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": x, "searchKey": sprintf("%s[%s].%s.image_pull_policy", [x, name, resource_prefix])}
}

checkPath(resource) = path {
	path := resource.spec.template.spec.container
} else = path {
	path := resource.spec.container
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Image Pull Policy Of The Container Is Not Set To Always"
# description: >-
#   Image Pull Policy of the container must be defined and set to Always
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.image_pull_policy_of_container_is_not_always"
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
image_pull_policy_of_container_is_not_always_snippet[violation] {
	image_pull_policy_of_container_is_not_always_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
