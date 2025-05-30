package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics.service_with_external_load_balancer.v2

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.terraform as tf_lib

service_with_external_load_balancer_inner[result] {
	resource := input.document[i].resource.kubernetes_service[name]
	resource.spec.type == "LoadBalancer"
	not common_lib.valid_key(resource.metadata, "annotations")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'metadata.annotations' is undefined", "keyExpectedValue": "'metadata.annotations' should be set", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_service", "searchKey": sprintf("kubernetes_service[%s].metadata.name", [name])}
}

service_with_external_load_balancer_inner[result] {
	resource := input.document[i].resource.kubernetes_service[name]
	common_lib.valid_key(resource.metadata, "annotations")
	not checkLoadBalancer(resource.metadata.annotations)
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("metadata.annotations is exposing a workload, not using an external Load Balancer provider by cloud provider", [name]), "keyExpectedValue": sprintf("metadata.annotations using an external Load Balancer provider by cloud provider", [name]), "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "kubernetes_service", "searchKey": sprintf("kubernetes_service[%s].metadata.name.annotations", [name])}
}

checkLoadBalancer(annotation) {
	annotation["networking.gke.io/load-balancer-type"] == "Internal"
}

checkLoadBalancer(annotation) {
	annotation["cloud.google.com/load-balancer-type"] == "Internal"
}

checkLoadBalancer(annotation) {
	annotation["service.beta.kubernetes.io/aws-load-balancer-internal"] == "true"
}

checkLoadBalancer(annotation) {
	annotation["service.beta.kubernetes.io/azure-load-balancer-internal"] == "true"
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Service With External Load Balancer"
# description: >-
#   Service has an external load balancer, which may cause accessibility from other networks and the Internet
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "kubernetes.kics.service_with_external_load_balancer"
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
service_with_external_load_balancer_snippet[violation] {
	service_with_external_load_balancer_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
