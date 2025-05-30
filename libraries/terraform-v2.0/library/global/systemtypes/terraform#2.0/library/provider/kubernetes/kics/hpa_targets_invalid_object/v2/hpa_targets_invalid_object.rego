package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.hpa_targets_invalid_object.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

hpa_targets_invalid_object_inner[result] {
	resource := input.document[i].resource.kubernetes_horizontal_pod_autoscaler[name]
	metric := resource.spec.metric
	not checkIsValidObject(metric)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_horizontal_pod_autoscaler[%s].spec.metric is a invalid object", [name]), "keyExpectedValue": sprintf("kubernetes_horizontal_pod_autoscaler[%s].spec.metric is a valid object", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_horizontal_pod_autoscaler", "searchKey": sprintf("kubernetes_horizontal_pod_autoscaler[%s].spec.metric", [name])}
}

checkIsValidObject(resource) {
	resource.type == "Object"
	resource.object != null
	resource.object.metric != null
	resource.object.target != null
	resource.object.described_object.name != null
	resource.object.described_object.api_version != null
	resource.object.described_object.kind != null
}

# METADATA: library-snippet
# version: v1
# title: "KICS: HPA Targets Invalid Object"
# description: >-
#   The Horizontal Pod Autoscaler must target a valid object
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.hpa_targets_invalid_object"
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
hpa_targets_invalid_object_snippet[violation] {
	hpa_targets_invalid_object_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
