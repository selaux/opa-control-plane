package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.cloud_storage_bucket_logging_not_enabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

cloud_storage_bucket_logging_not_enabled_inner[result] {
	resource := input.document[i].resource.google_storage_bucket[name]
	not common_lib.valid_key(resource, "logging")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "'google_storage_bucket.logging' is undefined", "keyExpectedValue": "'google_storage_bucket.logging' should be set", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "google_storage_bucket", "searchKey": sprintf("google_storage_bucket[%s]", [name])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Cloud Storage Bucket Logging Not Enabled"
# description: >-
#   Cloud storage bucket should have logging enabled
# severity: "high"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.cloud_storage_bucket_logging_not_enabled"
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
#       identifier: google_storage_bucket
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
cloud_storage_bucket_logging_not_enabled_snippet[violation] {
	cloud_storage_bucket_logging_not_enabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
