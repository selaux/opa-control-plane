package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.ingress_controller_exposes_workload.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

ingress_controller_exposes_workload_inner[result] {
	resource := input.document[i].resource.kubernetes_ingress[name]
	metadata := resource.metadata
	annotations := metadata.annotations
	common_lib.valid_key(annotations, "kubernetes.io/ingress.class")
	spec := resource.spec
	contentRule(spec)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("kubernetes_ingress[%s] is exposing the workload", [name]), "keyExpectedValue": sprintf("kubernetes_ingress[%s] should not be exposing the workload", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_ingress", "searchKey": sprintf("kubernetes_ingress[%s].spec.rule.http.path.backend", [name])}
}

ingressControllerExposesWorload(service_name, service_port) {
	services := input.document[i].resource.kubernetes_service[name]

	services.spec.port.target_port == service_port
	name == service_name
}

contentRule(spec) { #rule[r] and path
	is_array(spec.rule)
	backend := spec.rule[r].http.path.backend
	ingressControllerExposesWorload(backend.service_name, backend.service_port)
} #rule and path

else {
	backend := spec.rule.http.path.backend
	ingressControllerExposesWorload(backend.service_name, backend.service_port)
} #rule[r] and path[p]

else {
	is_array(spec.rule)
	is_array(spec.rule[r].http.path)
	backend := spec.rule[r].http.path[p].backend
	ingressControllerExposesWorload(backend.service_name, backend.service_port)
} #rule and path[p]

else {
	is_array(spec.rule.http.path)
	backend := spec.rule.http.path[p].backend
	ingressControllerExposesWorload(backend.service_name, backend.service_port)
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Ingress Controller Exposes Workload"
# description: >-
#   Ingress Controllers should not expose workload in order to avoid vulnerabilities and DoS attacks
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.ingress_controller_exposes_workload"
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
ingress_controller_exposes_workload_snippet[violation] {
	ingress_controller_exposes_workload_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
