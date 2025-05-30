package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.vm_with_full_cloud_access.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

vm_with_full_cloud_access_inner[result] {
	resource := input.document[i].resource.google_compute_instance[name]
	scopes := resource.service_account.scopes
	some j
	scopes[j] == "cloud-platform"
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": "'service_account.scopes' contains 'cloud-platform'", "keyExpectedValue": "'service_account.scopes' should not contain 'cloud-platform'", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_compute_instance", "searchKey": sprintf("google_compute_instance[%s].service_account.scopes", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: VM With Full Cloud Access"
# description: >-
#   A VM instance is configured to use the default service account with full access to all Cloud APIs
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.vm_with_full_cloud_access"
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
#       identifier: google_compute_instance
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
vm_with_full_cloud_access_snippet[violation] {
	vm_with_full_cloud_access_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
