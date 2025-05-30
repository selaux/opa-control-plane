package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.service_type_is_nodeport.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

service_type_is_nodeport_inner[result] {
	resource := input.document[i].resource.kubernetes_service[name]
	resource.spec.type == "NodePort"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_service[%s].spec.type is 'NodePort'", [name]), "keyExpectedValue": sprintf("kubernetes_service[%s].spec.type should not be 'NodePort'", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_service", "searchKey": sprintf("kubernetes_service[%s].spec.type", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Service Type is NodePort"
# description: >-
#   Service type should not be NodePort
# severity: "low"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.service_type_is_nodeport"
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
service_type_is_nodeport_snippet[violation] {
	service_type_is_nodeport_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
