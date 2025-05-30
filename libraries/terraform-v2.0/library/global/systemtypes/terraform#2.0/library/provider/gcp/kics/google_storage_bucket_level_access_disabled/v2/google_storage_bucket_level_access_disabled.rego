package global.systemtypes["terraform:2.0"].library.provider.gcp.kics.google_storage_bucket_level_access_disabled.v2

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.common as common_lib
import data.global.systemtypes["terraform:2.0"].library.provider.gcp.kics_libs.terraform as tf_lib

google_storage_bucket_level_access_disabled_inner[result] {
	storageBucket := input.document[i].resource.google_storage_bucket[name]
	storageBucket.uniform_bucket_level_access == false
	result := {"documentId": input.document[i].id, "issueType": "IncorrectValue", "keyActualValue": sprintf("google_storage_bucket[%s].uniform_bucket_level_access is false", [name]), "keyExpectedValue": sprintf("google_storage_bucket[%s].uniform_bucket_level_access should be true", [name]), "remediation": json.marshal({"after": "true", "before": "false"}), "remediationType": "replacement", "resourceName": tf_lib.get_resource_name(storageBucket, name), "resourceType": "google_storage_bucket", "searchKey": sprintf("google_storage_bucket[%s].uniform_bucket_level_access", [name]), "searchLine": common_lib.build_search_line(["resource", "google_storage_bucket", name, "uniform_bucket_level_access"], [])}
}

google_storage_bucket_level_access_disabled_inner[result] {
	storageBucket := input.document[i].resource.google_storage_bucket[name]
	not common_lib.valid_key(storageBucket, "uniform_bucket_level_access")
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": sprintf("google_storage_bucket[%s].uniform_bucket_level_access is undefined or null", [name]), "keyExpectedValue": sprintf("google_storage_bucket[%s].uniform_bucket_level_access should be defined and not null", [name]), "remediation": "uniform_bucket_level_access = true", "remediationType": "addition", "resourceName": tf_lib.get_resource_name(storageBucket, name), "resourceType": "google_storage_bucket", "searchKey": sprintf("google_storage_bucket[%s]", [name]), "searchLine": common_lib.build_search_line(["resource", "google_storage_bucket", name], [])}
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Google Storage Bucket Level Access Disabled"
# description: >-
#   Google Storage Bucket Level Access should be enabled
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "gcp.kics.google_storage_bucket_level_access_disabled"
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
google_storage_bucket_level_access_disabled_snippet[violation] {
	google_storage_bucket_level_access_disabled_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
