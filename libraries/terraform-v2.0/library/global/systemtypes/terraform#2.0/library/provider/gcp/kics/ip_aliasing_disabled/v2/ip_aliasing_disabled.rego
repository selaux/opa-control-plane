package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.ip_aliasing_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

ip_aliasing_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not resource.ip_allocation_policy
	not resource.networking_mode
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attributes 'ip_allocation_policy' and 'networking_mode' are undefined", "keyExpectedValue": "Attributes 'ip_allocation_policy' and 'networking_mode' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary])}
}

ip_aliasing_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not resource.ip_allocation_policy
	resource.networking_mode
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'ip_allocation_policy' is undefined", "keyExpectedValue": "Attribute 'ip_allocation_policy' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary])}
}

ip_aliasing_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.ip_allocation_policy
	resource.networking_mode == "ROUTES"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'networking_mode' is ROUTES", "keyExpectedValue": "Attribute 'networking_mode' should be VPC_NATIVE", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: IP Aliasing Disabled"
# description: >-
#   Kubernetes Clusters must be created with Alias IP ranges enabled, which means the attribute 'ip_allocation_policy' must be defined and, if defined, the attribute 'networking_mode' must be VPC_NATIVE
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.ip_aliasing_disabled"
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
#     name: "google"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - argument: ""
#       identifier: google_container_cluster
#       name: ""
#       scope: resource
#       service: ""
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
ip_aliasing_disabled_snippet[violation] {
	ip_aliasing_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
