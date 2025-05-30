package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.stackdriver_monitoring_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

stackdriver_monitoring_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	not resource.monitoring_service
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Attribute 'monitoring_service' is undefined", "keyExpectedValue": "Attribute 'monitoring_service' should be defined", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary])}
}

stackdriver_monitoring_disabled_inner[result] {
	resource := input.document[i].resource.google_container_cluster[primary]
	resource.monitoring_service == "none"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "Attribute 'monitoring_service' is 'none'", "keyExpectedValue": "Attribute 'monitoring_service' should not be 'none'", "resourceName": tf_lib.get_resource_name(resource, primary), "resourceType": "google_container_cluster", "searchKey": sprintf("google_container_cluster[%s]", [primary])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Stackdriver Monitoring Disabled"
# description: >-
#   Kubernetes Engine Clusters must have Stackdriver Monitoring enabled, which means the attribute 'monitoring_service' must be defined and different than 'none'
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.stackdriver_monitoring_disabled"
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
stackdriver_monitoring_disabled_snippet[violation] {
	stackdriver_monitoring_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
